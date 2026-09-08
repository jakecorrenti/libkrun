// Verify virtio-blk serves concurrent guest reads with out-of-order completion.
//
// Attaches a host-side direct-I/O raw disk, fills it with a deterministic
// per-sector pattern, and checks both data integrity and aggregate read
// throughput with four parallel guest readers.

use macros::{guest, host};

pub struct TestBlkParallelReads;

#[host]
mod host {
    use super::*;

    const DISK_BYTES: u64 = 128 * 1024 * 1024;
    const SECTOR_SIZE: u64 = 512;

    use crate::common;
    use crate::{ShouldRun, Test, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    type KrunAddDisk3Fn = unsafe extern "C" fn(
        ctx_id: u32,
        block_id: *const std::ffi::c_char,
        disk_path: *const std::ffi::c_char,
        disk_format: u32,
        read_only: bool,
        direct_io: bool,
        sync_mode: u32,
    ) -> i32;

    fn get_krun_add_disk3() -> KrunAddDisk3Fn {
        let symbol = CString::new("krun_add_disk3").unwrap();
        let ptr = unsafe { nix::libc::dlsym(nix::libc::RTLD_DEFAULT, symbol.as_ptr()) };
        assert!(!ptr.is_null(), "krun_add_disk3 not found");
        unsafe { std::mem::transmute(ptr) }
    }

    fn create_raw_disk(path: &str) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .expect("open raw disk");
        file.set_len(DISK_BYTES).expect("set_len on raw disk");

        let sectors = DISK_BYTES / SECTOR_SIZE;
        let mut sector_buf = [0u8; SECTOR_SIZE as usize];
        for sector in 0..sectors {
            sector_buf[..8].copy_from_slice(&sector.to_le_bytes());
            file.write_all(&sector_buf).expect("write sector pattern");
        }
        file.sync_all().expect("sync raw disk");
    }

    impl Test for TestBlkParallelReads {
        fn should_run(&self) -> ShouldRun {
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_BLK.into())) }.ok() != Some(1)
            {
                return ShouldRun::No("libkrun compiled without BLK");
            }
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            60
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let krun_add_disk3 = get_krun_add_disk3();
            let disk_path = format!("{}/blk-perf.raw", test_setup.tmp_dir.display());
            create_raw_disk(&disk_path);

            let root_dir = common::setup_rootfs(&test_setup)?;
            let root_path = CString::new(root_dir.as_os_str().as_bytes())?;
            let disk_path = CString::new(disk_path)?;
            let init_config = common::build_init_config(&test_setup.test_case, &[]);

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 4, 1024))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                krun_call!(krun_add_virtiofs3(
                    ctx,
                    c"/dev/root".as_ptr(),
                    root_path.as_ptr(),
                    0,
                    false,
                ))?;
                krun_call!(krun_add_disk3(
                    ctx,
                    c"disk".as_ptr(),
                    disk_path.as_ptr(),
                    KRUN_DISK_FORMAT_RAW,
                    true,
                    true,
                    KRUN_SYNC_NONE,
                ))?;
                init_config
                    .apply(std::ptr::null_mut(), ctx, "/dev/root")
                    .expect("apply init config");
                krun_call!(krun_start_enter(ctx))?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    const READERS: u64 = 4;
    const CHUNK: u64 = 1024 * 1024;
    const CHUNKS_PER_READER: u64 = 16; // 16 MiB per reader
    const BYTES_PER_READER: u64 = CHUNK * CHUNKS_PER_READER;
    const MIN_PARALLEL_SPEEDUP: f64 = 1.5;
    const DISK_BYTES: u64 = 128 * 1024 * 1024;
    const SECTOR_SIZE: u64 = 512;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    use std::thread;
    use std::time::Instant;

    fn open_block_device_direct() -> std::fs::File {
        for _ in 0..100 {
            if let Ok(file) = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECT)
                .open("/dev/vda")
            {
                return file;
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("timed out waiting for /dev/vda");
    }

    fn open_block_device() -> std::fs::File {
        for _ in 0..100 {
            if let Ok(file) = OpenOptions::new().read(true).open("/dev/vda") {
                return file;
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("timed out waiting for /dev/vda");
    }

    fn aligned_chunk() -> Vec<u8> {
        let layout =
            std::alloc::Layout::from_size_align(CHUNK as usize, 4096).expect("chunk layout");
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null(), "failed to allocate aligned read buffer");
        unsafe { Vec::from_raw_parts(ptr, CHUNK as usize, CHUNK as usize) }
    }

    fn read_region(file: &mut std::fs::File, start_sector: u64, buf: &mut [u8]) {
        for i in 0..CHUNKS_PER_READER {
            let sector = start_sector + i * (CHUNK / SECTOR_SIZE);
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE))
                .expect("seek during read");
            file.read_exact(buf).expect("read block data");
        }
    }

    fn verify_pattern(file: &mut std::fs::File) {
        let mut buf = [0u8; SECTOR_SIZE as usize];
        let sample_sectors = [0, 1024, 64 * 1024, (DISK_BYTES / SECTOR_SIZE) - 1];
        for sector in sample_sectors {
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE))
                .expect("seek for verify");
            file.read_exact(&mut buf).expect("read for verify");
            let got = u64::from_le_bytes(buf[..8].try_into().unwrap());
            assert_eq!(got, sector, "unexpected data at sector {sector}");
        }
    }

    fn throughput_mib_s(bytes: u64, elapsed: std::time::Duration) -> f64 {
        bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0)
    }

    impl Test for TestBlkParallelReads {
        fn in_guest(self: Box<Self>) {
            let mut verify_file = open_block_device();
            verify_pattern(&mut verify_file);

            let mut single_file = open_block_device_direct();
            let mut single_buf = aligned_chunk();
            let single_start = Instant::now();
            read_region(&mut single_file, 0, &mut single_buf);
            let single_elapsed = single_start.elapsed();
            let single_rate = throughput_mib_s(BYTES_PER_READER, single_elapsed);

            let parallel_start = Instant::now();
            thread::scope(|scope| {
                for reader in 0..READERS {
                    scope.spawn(move || {
                        let mut file = open_block_device_direct();
                        let mut buf = aligned_chunk();
                        let start_sector = reader * (BYTES_PER_READER / SECTOR_SIZE);
                        read_region(&mut file, start_sector, &mut buf);
                    });
                }
            });
            let parallel_elapsed = parallel_start.elapsed();
            let parallel_rate = throughput_mib_s(BYTES_PER_READER * READERS, parallel_elapsed);

            assert!(
                parallel_rate >= single_rate * MIN_PARALLEL_SPEEDUP,
                "parallel read throughput too low: {parallel_rate:.1} MiB/s aggregate vs \
                 {single_rate:.1} MiB/s single (need >= {MIN_PARALLEL_SPEEDUP}x)"
            );

            println!("OK");
        }
    }
}
