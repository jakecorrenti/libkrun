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

pub type IoctlNr = libc::c_ulong;

pub const _IOC_NONE: libc::c_uint = 0;
pub const _IOC_NRSHIFT: libc::c_uint = 0;
pub const _IOC_TYPESHIFT: libc::c_uint = 8;
pub const _IOC_SIZESHIFT: libc::c_uint = 16;
pub const _IOC_DIRSHIFT: libc::c_uint = 30;

/// Raw macro to declare the expression that calculates an ioctl number
#[macro_export]
macro_rules! ioctl_expr {
    ($dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        ((($dir as $crate::virtio::block::disk::base::sys::unix::IoctlNr)
            << $crate::virtio::block::disk::base::sys::unix::_IOC_DIRSHIFT)
            | (($ty as $crate::virtio::block::disk::base::sys::unix::IoctlNr)
                << $crate::virtio::block::disk::base::sys::unix::_IOC_TYPESHIFT)
            | (($nr as $crate::virtio::block::disk::base::sys::unix::IoctlNr)
                << $crate::virtio::block::disk::base::sys::unix::_IOC_NRSHIFT)
            | (($size as $crate::virtio::block::disk::base::sys::unix::IoctlNr)
                << $crate::virtio::block::disk::base::sys::unix::_IOC_SIZESHIFT))
    };
}

/// Raw macro to declare a constant or a function that returns an ioctl number.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        /// Constant ioctl request number.
        pub const $name: $crate::virtio::block::disk::base::sys::unix::IoctlNr = $crate::ioctl_expr!($dir, $ty, $nr, $size);
    };
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        /// Generates ioctl request number.
        pub const fn $name($($v: ::std::os::raw::c_uint),+) -> $crate::virtio::block::disk::base::sys::unix::IoctlNr {
            $crate::ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
}

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        $crate::ioctl_ioc_nr!($name, $crate::virtio::block::disk::base::sys::unix::_IOC_NONE, $ty, $nr, 0);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        $crate::ioctl_ioc_nr!($name, $crate::virtio::block::disk::base::sys::unix::_IOC_NONE, $ty, $nr, 0, $($v),+);
    };
}
