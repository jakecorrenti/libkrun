use crate::syscall;
use crate::virtio::block::disk::base::descriptor::{
    AsRawDescriptor, RawDescriptor, SafeDescriptor,
};
use serde::Serializer;
use std::cell::RefCell;
use std::cmp::min;
use std::mem::MaybeUninit;
use std::os::unix::fs::FileExt;

pub mod sys;

thread_local! {
    static DESCRIPTOR_DST: RefCell<Option<Vec<RawDescriptor>>> = Default::default();
}

thread_local! {
    static DESCRIPTOR_SRC: RefCell<Option<Vec<Option<SafeDescriptor>>>> = Default::default();
}

pub mod errno {
    use std::convert::From;
    use std::convert::TryInto;
    use std::fmt;
    use std::fmt::Display;
    use std::io;

    use serde::Deserialize;
    use serde::Serialize;
    use thiserror::Error;

    /// A system error
    /// In Unix systems, retrieved from errno (man 3 errno), set by a libc
    /// function that returned an error.
    /// On Windows, retrieved from GetLastError, set by a Windows function
    /// that returned an error
    #[derive(Error, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
    #[serde(transparent)]
    pub struct Error(i32);
    pub type Result<T> = std::result::Result<T, Error>;

    impl Error {
        /// Constructs a new error with the given error number.
        pub fn new<T: TryInto<i32>>(e: T) -> Error {
            // A value outside the bounds of an i32 will never be a valid
            // errno/GetLastError
            Error(e.try_into().unwrap_or_default())
        }

        /// Constructs an Error from the most recent system error.
        ///
        /// The result of this only has any meaning just after a libc/Windows call that returned
        /// a value indicating errno was set.
        pub fn last() -> Error {
            Error(io::Error::last_os_error().raw_os_error().unwrap())
        }

        /// Gets the errno for this error
        pub fn errno(self) -> i32 {
            self.0
        }
    }

    impl From<io::Error> for Error {
        fn from(e: io::Error) -> Self {
            Error(e.raw_os_error().unwrap_or_default())
        }
    }

    impl From<Error> for io::Error {
        fn from(e: Error) -> io::Error {
            io::Error::from_raw_os_error(e.0)
        }
    }

    impl From<Error> for Box<dyn std::error::Error + Send> {
        fn from(e: Error) -> Self {
            Box::new(e)
        }
    }

    impl Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Into::<io::Error>::into(*self).fmt(f)
        }
    }

    /// Returns the last errno as a Result that is always an error.
    pub fn errno_result<T>() -> Result<T> {
        Err(Error::last())
    }
}

pub mod descriptor {
    use std::fs::File;
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::IntoRawFd;
    use std::os::fd::RawFd;
    use std::sync::Arc;

    use serde::Deserialize;
    use serde::Serialize;
    use serde::Serializer;

    pub type RawDescriptor = RawFd;

    /// Wraps a RawDescriptor and safely closes it when self falls out of scope.
    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    #[serde(transparent)]
    pub struct SafeDescriptor {
        #[serde(with = "super::with_raw_descriptor")]
        pub(crate) descriptor: RawDescriptor,
    }

    /// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
    pub trait IntoRawDescriptor {
        fn into_raw_descriptor(self) -> RawDescriptor;
    }

    /// Trait for returning the underlying raw descriptor, without giving up ownership of the
    /// descriptor.
    pub trait AsRawDescriptor {
        /// Returns the underlying raw descriptor.
        ///
        /// Since the descriptor is still owned by the provider, callers should not assume that it will
        /// remain open for longer than the immediate call of this method. In particular, it is a
        /// dangerous practice to store the result of this method for future use: instead, it should be
        /// used to e.g. obtain a raw descriptor that is immediately passed to a system call.
        ///
        /// If you need to use the descriptor for a longer time (and particularly if you cannot reliably
        /// track the lifetime of the providing object), you should probably consider using
        /// [`SafeDescriptor`] (possibly along with [`trait@IntoRawDescriptor`]) to get full ownership
        /// over a descriptor pointing to the same resource.
        fn as_raw_descriptor(&self) -> RawDescriptor;
    }

    /// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
    pub trait AsRawDescriptors {
        /// Returns the underlying raw descriptors.
        ///
        /// Please refer to the documentation of [`AsRawDescriptor::as_raw_descriptor`] for limitations
        /// and recommended use.
        fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
    }

    pub trait FromRawDescriptor {
        /// # Safety
        /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
        /// `from_raw_descriptor`
        unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
    }

    impl AsRawDescriptor for SafeDescriptor {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.descriptor
        }
    }

    impl<T> AsRawDescriptor for Arc<T>
    where
        T: AsRawDescriptor,
    {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.as_ref().as_raw_descriptor()
        }
    }

    impl<T> AsRawDescriptors for T
    where
        T: AsRawDescriptor,
    {
        fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
            vec![self.as_raw_descriptor()]
        }
    }

    impl IntoRawDescriptor for SafeDescriptor {
        fn into_raw_descriptor(self) -> RawDescriptor {
            let descriptor = self.descriptor;
            mem::forget(self);
            descriptor
        }
    }

    impl FromRawDescriptor for SafeDescriptor {
        unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
            SafeDescriptor { descriptor }
        }
    }

    impl From<SafeDescriptor> for File {
        fn from(s: SafeDescriptor) -> File {
            // SAFETY:
            // Safe because we own the SafeDescriptor at this point.
            unsafe { File::from_raw_fd(s.into_raw_descriptor()) }
        }
    }

    macro_rules! into_raw_descriptor {
        ($name:ident) => {
            impl IntoRawDescriptor for $name {
                fn into_raw_descriptor(self) -> RawDescriptor {
                    self.into_raw_fd()
                }
            }
        };
    }
    macro_rules! as_raw_descriptor {
        ($name:ident) => {
            impl AsRawDescriptor for $name {
                fn as_raw_descriptor(&self) -> RawDescriptor {
                    self.as_raw_fd()
                }
            }
        };
    }

    macro_rules! from_raw_descriptor {
        ($name:ident) => {
            impl FromRawDescriptor for $name {
                unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
                    $name::from_raw_fd(descriptor)
                }
            }
        };
    }

    into_raw_descriptor!(File);
    as_raw_descriptor!(File);
    from_raw_descriptor!(File);

    #[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(transparent)]
    pub struct Descriptor(pub RawDescriptor);
    impl AsRawDescriptor for Descriptor {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.0
        }
    }
    impl FromRawDescriptor for Descriptor {
        unsafe fn from_raw_descriptor(desc: RawDescriptor) -> Self {
            Descriptor(desc)
        }
    }

    impl Serialize for Descriptor {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_u64(self.0 as u64)
        }
    }

    impl<'de> Deserialize<'de> for Descriptor {
        fn deserialize<D>(deserializer: D) -> Result<Descriptor, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            u64::deserialize(deserializer).map(|data| Descriptor(data as RawDescriptor))
        }
    }
}

/// Serializes a descriptor for later retrieval in a parent `SerializeDescriptors` struct.
///
/// If there is no parent `SerializeDescriptors` being serialized, this will return an error.
///
/// For convenience, it is recommended to use the `with_raw_descriptor` module in a `#[serde(with =
/// "...")]` attribute which will make use of this function.
pub fn serialize_descriptor<S: Serializer>(
    rd: &RawDescriptor,
    se: S,
) -> std::result::Result<S::Ok, S::Error> {
    let index = push_descriptor(*rd).map_err(serde::ser::Error::custom)?;
    se.serialize_u32(index.try_into().map_err(|_| {
        serde::ser::Error::custom("attempt to serialize too many descriptors at once")
    })?)
}

/// Pushes a descriptor on the thread local destination of descriptors, returning the index in which
/// the descriptor was pushed.
//
/// Returns Err if the thread local destination was not already initialized.
fn push_descriptor(rd: RawDescriptor) -> Result<usize, &'static str> {
    DESCRIPTOR_DST.with(|d| {
        d.borrow_mut()
            .as_mut()
            .ok_or("attempt to serialize descriptor without descriptor destination")
            .map(|descriptors| {
                let index = descriptors.len();
                descriptors.push(rd);
                index
            })
    })
}

/// Takes a descriptor at the given index from the thread local source of descriptors.
//
/// Returns None if the thread local source was not already initialized.
fn take_descriptor(index: usize) -> Result<SafeDescriptor, &'static str> {
    DESCRIPTOR_SRC.with(|d| {
        d.borrow_mut()
            .as_mut()
            .ok_or("attempt to deserialize descriptor without descriptor source")?
            .get_mut(index)
            .ok_or("attempt to deserialize out of bounds descriptor")?
            .take()
            .ok_or("attempt to deserialize descriptor that was already taken")
    })
}

/// Module that exports `serialize`/`deserialize` functions for use with `#[serde(with = "...")]`
/// attribute. It only works with fields with `RawDescriptor` type.
pub mod with_raw_descriptor {
    use super::descriptor::IntoRawDescriptor;
    use super::descriptor::{RawDescriptor, SafeDescriptor};
    pub use super::serialize_descriptor as serialize;
    use crate::virtio::block::disk::base::take_descriptor;
    use serde::de;
    use serde::de::Error;
    use serde::Deserializer;

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<RawDescriptor, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_descriptor(de).map(IntoRawDescriptor::into_raw_descriptor)
    }

    /// Deserializes a descriptor provided via `deserialize_with_descriptors`.
    ///
    /// If `deserialize_with_descriptors` is not in the call chain, this will return an error.
    ///
    /// For convenience, it is recommended to use the `with_raw_descriptor` module in a `#[serde(with =
    /// "...")]` attribute which will make use of this function.
    pub fn deserialize_descriptor<'de, D>(de: D) -> std::result::Result<SafeDescriptor, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DescriptorVisitor;

        impl<'de> serde::de::Visitor<'de> for DescriptorVisitor {
            type Value = u32;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer which fits into a u32")
            }

            fn visit_u8<E: de::Error>(self, value: u8) -> Result<Self::Value, E> {
                Ok(value as _)
            }

            fn visit_u16<E: de::Error>(self, value: u16) -> Result<Self::Value, E> {
                Ok(value as _)
            }

            fn visit_u32<E: de::Error>(self, value: u32) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_i8<E: de::Error>(self, value: i8) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_i16<E: de::Error>(self, value: i16) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_i32<E: de::Error>(self, value: i32) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }

            fn visit_i128<E: de::Error>(self, value: i128) -> Result<Self::Value, E> {
                value.try_into().map_err(E::custom)
            }
        }

        let index = de.deserialize_u32(DescriptorVisitor)? as usize;
        take_descriptor(index).map_err(D::Error::custom)
    }
}

/// A trait for writing zeroes to an arbitrary position in a file.
pub trait WriteZeroesAt {
    /// Write up to `length` bytes of zeroes starting at `offset`, returning how many bytes were
    /// written.
    fn write_zeroes_at(&self, offset: u64, length: usize) -> std::io::Result<usize>;

    /// Write zeroes starting at `offset` until `length` bytes have been written.
    ///
    /// This method will continuously call `write_zeroes_at` until the requested
    /// `length` is satisfied or an error is encountered.
    fn write_zeroes_all_at(&self, mut offset: u64, mut length: usize) -> std::io::Result<()> {
        while length > 0 {
            match self.write_zeroes_at(offset, length) {
                Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                Ok(bytes_written) => {
                    length = length
                        .checked_sub(bytes_written)
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;
                    offset = offset
                        .checked_add(bytes_written as u64)
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}

/// THIS IS A LINUX IMPLEMENTATION... THE CROSVM MAC IMPLEMENTATION WAS A TODO!()
pub(crate) fn file_write_zeroes_at(
    file: &std::fs::File,
    offset: u64,
    length: usize,
) -> std::io::Result<usize> {
    // fall back to write()
    // fallocate() failed; fall back to writing a buffer of zeroes
    // until we have written up to length.
    let buf_size = min(length, 0x10000);
    let buf = vec![0u8; buf_size];
    let mut nwritten: usize = 0;
    while nwritten < length {
        let remaining = length - nwritten;
        let write_size = min(remaining, buf_size);
        nwritten += file.write_at(&buf[0..write_size], offset + nwritten as u64)?;
    }
    Ok(length)
}

/// THIS IS A LINUX IMPLEMENTATION... THE CROSVM MAC IMPLEMENTATION WAS A TODO!()
pub(crate) fn file_punch_hole(
    file: &std::fs::File,
    offset: u64,
    length: u64,
) -> std::io::Result<()> {
    if crate::virtio::block::disk::base::sys::linux::is_block_file(file)? {
        Ok(crate::virtio::block::disk::base::sys::linux::discard_block(
            file, offset, length,
        )?)
    } else {
        crate::virtio::block::disk::base::sys::linux::fallocate(
            file,
            crate::virtio::block::disk::base::sys::linux::FallocateMode::PunchHole,
            offset,
            length,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.errno()))
    }
}

impl WriteZeroesAt for std::fs::File {
    fn write_zeroes_at(&self, offset: u64, length: usize) -> std::io::Result<usize> {
        file_write_zeroes_at(self, offset, length)
    }
}

/// A trait for deallocating space in a file.
pub trait PunchHole {
    /// Replace a range of bytes with a hole.
    fn punch_hole(&self, offset: u64, length: u64) -> std::io::Result<()>;
}

impl PunchHole for std::fs::File {
    fn punch_hole(&self, offset: u64, length: u64) -> std::io::Result<()> {
        file_punch_hole(self, offset, length)
    }
}
