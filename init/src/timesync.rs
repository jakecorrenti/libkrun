/// Guest-side time-synchronisation worker.
///
/// The hypervisor sends 8-byte little-endian nanosecond timestamps over a
/// `SOCK_DGRAM` vsock socket on port 123 (well-known NTP port).  When the
/// delta between the host timestamp and the current guest clock exceeds 100 ms
/// the guest clock is stepped to the host value.
///
/// The worker runs in a forked child process that never returns; the parent
/// carries on to exec the workload.
use std::io;
use std::mem;
use std::os::fd::AsRawFd;

use anyhow::Context;
use rustix::net::{self, AddressFamily, RecvFlags, SocketType};
use rustix::time::{self, ClockId, Nsecs, Secs, Timespec};

const TSYNC_PORT: u32 = 123;
const BUFSIZE: usize = 8;
const NANOS_IN_SECOND: u64 = 1_000_000_000;
/// Step the clock only when the absolute delta exceeds 100 ms.
const DELTA_SYNC: u64 = 100_000_000;

/// Spawns a detached child process that runs the clock-sync loop.
/// The child never returns; the parent returns immediately.
pub fn spawn() {
    // SAFETY: standard fork precautions; the child either runs the sync loop
    // or immediately calls _exit.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            // Child: run the sync loop; _exit on any error.
            if let Err(e) = run() {
                eprintln!("timesync: {e:#}");
            }
            unsafe { libc::_exit(1) };
        }
        p if p < 0 => eprintln!("timesync: fork: {}", io::Error::last_os_error()),
        _ => {} // Parent: continue.
    }
}

/// Opens a vsock DGRAM socket, binds to TSYNC_PORT, and loops forever
/// adjusting CLOCK_REALTIME when the host-provided timestamp diverges.
fn run() -> anyhow::Result<()> {
    let sock = net::socket(AddressFamily::VSOCK, SocketType::DGRAM, None)
        .context("creating vsock DGRAM socket")?;

    // sockaddr_vm: svm_family, svm_reserved1, svm_port, svm_cid, svm_flags, svm_zero[3].
    // Use MaybeUninit + zeroed to avoid referencing an uninitialised value
    // before all fields are set.
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = TSYNC_PORT;
    addr.svm_cid = libc::VMADDR_CID_HOST;

    // rustix has no SocketAddrVsock, so we call libc::bind directly.
    // SAFETY: `addr` is a correctly initialised `sockaddr_vm`; size matches.
    let ret = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("binding vsock to port {TSYNC_PORT}"));
    }

    let mut buf = [0u8; BUFSIZE];

    loop {
        let (n, _) = net::recv(&sock, &mut buf, RecvFlags::empty()).context("recv on vsock")?;

        if n != BUFSIZE {
            eprintln!("timesync: ignoring bogus packet ({n} bytes)");
            continue;
        }

        // The host timestamp is a little-endian u64 of nanoseconds since epoch.
        let htime_ns = u64::from_le_bytes(buf);

        // Read the current guest clock.
        let gtime = time::clock_gettime(ClockId::Realtime);
        let gtime_ns = (gtime.tv_sec as u64) * NANOS_IN_SECOND + gtime.tv_nsec as u64;

        // Step the clock only when the delta exceeds the threshold.
        if htime_ns.abs_diff(gtime_ns) > DELTA_SYNC {
            let htime = Timespec {
                tv_sec: (htime_ns / NANOS_IN_SECOND) as Secs,
                tv_nsec: (htime_ns % NANOS_IN_SECOND) as Nsecs,
            };
            time::clock_settime(ClockId::Realtime, htime).context("clock_settime")?;
        }
    }
}
