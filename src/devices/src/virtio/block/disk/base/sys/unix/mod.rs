pub mod fcntl;

#[macro_export]
macro_rules! syscall {
    ($e:expr) => {{
        let res = $e;
        if res < 0 {
            $crate::virtio::block::disk::base::errno::errno_result()
        } else {
            Ok(res)
        }
    }};
}