pub mod cache;
pub mod threads;

use super::BlockResult;
use super::BlockError;
use futures::io::{IoSlice, IoSliceMut};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::alloc::{self, GlobalAlloc};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::sync::oneshot;

use super::qcow2::file::*;

pub use cache::*;
pub use threads::*;

pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub type BlockFutureResult<'a, T> = BoxedFuture<'a, BlockResult<T>>;

/// Boxed future type for functions that are infallible
pub type InfallibleFuture<'a> = BoxedFuture<'a, ()>;

#[macro_export]
macro_rules! numerical_enum {
    (
        $(#[$attr:meta])*
        pub enum $enum_name:ident as $repr:tt {
            $(
                $(#[$id_attr:meta])*
                $identifier:ident = $value:literal,
            )+
        }
    ) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr($repr)]
        pub enum $enum_name {
            $(
                $(#[$id_attr])*
                $identifier = $value,
            )+
        }

        impl TryFrom<$repr> for $enum_name {
            type Error = $crate::virtio::block::disk::BlockError;
            fn try_from(val: $repr) -> $crate::virtio::block::disk::BlockResult<Self> {
                match val {
                    $($value => Ok($enum_name::$identifier),)*
                    _ => Err($crate::virtio::block::disk::BlockError::from_desc(format!(
                        "Invalid value for {}: {:x}",
                        stringify!($enum_name),
                        val
                    ))),
                }
            }
        }
    }
}

pub trait FlatSize {
    const SIZE: usize;
}

// TODO: Should be a procedural (derivable) macro
#[macro_export]
macro_rules! flat_size {
    (
        $(#[$attr:meta])*
        pub struct $struct_name:ident {
            $(pub $identifier:ident: $type:ty,)+
        }
    ) => {
        $(#[$attr])*
        pub struct $struct_name {
            $(pub $identifier: $type,)+
        }

        impl $crate::helpers::FlatSize for $struct_name {
            const SIZE: usize = $(<$type>::SIZE +)+ 0;
        }
    }
}

macro_rules! impl_flat_size_for_primitive {
    ($type:tt) => {
        impl $crate::virtio::block::disk::helpers::FlatSize for $type {
            const SIZE: usize = std::mem::size_of::<Self>();
        }
    };
}

impl_flat_size_for_primitive!(u8);
impl_flat_size_for_primitive!(u16);
impl_flat_size_for_primitive!(u32);
impl_flat_size_for_primitive!(u64);
impl_flat_size_for_primitive!(usize);
impl_flat_size_for_primitive!(i8);
impl_flat_size_for_primitive!(i16);
impl_flat_size_for_primitive!(i32);
impl_flat_size_for_primitive!(i64);
impl_flat_size_for_primitive!(isize);

impl_flat_size_for_primitive!([u8; 1]);
impl_flat_size_for_primitive!([u8; 2]);
impl_flat_size_for_primitive!([u8; 3]);
impl_flat_size_for_primitive!([u8; 4]);


#[macro_export]
macro_rules! splittable_enum {
    (
        $(#[$attr:meta])*
        pub enum $enum_name:ident {
            $(
                $(#[cfg($cfg_attr:meta)])*
                $variant:ident($encapsulated:path),
            )+
        }
    ) => {
        $(#[$attr])*
        pub enum $enum_name {
            $(
                $(#[cfg($cfg_attr)])*
                $variant($encapsulated),
            )+
        }

        $(
            $(#[cfg($cfg_attr)])*
            impl TryFrom<$enum_name> for $encapsulated {
                type Error = $crate::virtio::block::disk::BlockError;
                fn try_from(val: $enum_name) -> $crate::virtio::block::disk::BlockResult<$encapsulated> {
                    match val {
                        $enum_name::$variant(obj) => Ok(obj),
                        #[allow(unreachable_patterns)]
                        _ => Err(format!(
                                "{:?} is not of variant {}",
                                val,
                                stringify!($variant),
                            ).into()),
                    }
                }
            }
        )*

        $(
            $(#[cfg($cfg_attr)])*
            impl<'a> TryFrom<&'a $enum_name> for &'a $encapsulated {
                type Error = $crate::virtio::block::disk::BlockError;
                fn try_from(val: &'a $enum_name) -> $crate::virtio::block::disk::BlockResult<&'a $encapsulated> {
                    match val {
                        $enum_name::$variant(obj) => Ok(obj),
                        #[allow(unreachable_patterns)]
                        _ => Err(format!(
                                "{:?} is not of variant {}",
                                val,
                                stringify!($variant),
                            ).into()),
                    }
                }
            }
        )*

        $(
            $(#[cfg($cfg_attr)])*
            impl<'a> TryFrom<&'a mut $enum_name> for &'a  mut$encapsulated {
                type Error = $crate::virtio::block::disk::BlockError;
                fn try_from(val: &'a mut $enum_name) -> $crate::virtio::block::disk::BlockResult<&'a mut $encapsulated> {
                    match val {
                        $enum_name::$variant(obj) => Ok(obj),
                        #[allow(unreachable_patterns)]
                        _ => Err(format!(
                                "{:?} is not of variant {}",
                                val,
                                stringify!($variant),
                            ).into()),
                    }
                }
            }
        )*

        $(
            $(#[cfg($cfg_attr)])*
            impl From<$encapsulated> for $enum_name {
                fn from(val: $encapsulated) -> $enum_name {
                    $enum_name::$variant(val)
                }
            }
        )*
    }
}


pub trait IteratorExtensions: Iterator {
    fn try_any<E, F: FnMut(<Self as Iterator>::Item) -> Result<bool, E>>(
        &mut self,
        mut f: F,
    ) -> Result<bool, E> {
        for x in self {
            if f(x)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl<I: Iterator> IteratorExtensions for I {}


/// Iterates over a `Vec<W>`, where `W` is a type that (by reference) can be converted to an
/// `Option<S>`, using a function `Fn(&W) -> Option<S>`.  Whenever this function returns `None` for
/// an element of the vector, that element is removed (using `swap_remove()`).
/// The idea is that `W` is a weak reference that can be upgraded to a strong reference `S`.
///
/// Example use cases:
/// - `W` is `sync::Weak<V>`, `S` is `Arc<V>`, `F` is `sync::Weak::upgrade`
/// - `W` is `rc::Weak<V>`, `S` is `Rc<V>`, `F` is `rc::Weak::upgrade`
pub struct WeakAutoDeleteIterator<'a, W, S, F: Fn(&W) -> Option<S>> {
    vec: &'a mut Vec<W>,
    index: usize,
    upgrade: F,
}


impl<'a, W, S, F: Fn(&W) -> Option<S>> WeakAutoDeleteIterator<'a, W, S, F> {
    /// Create a `WeakAutoDeleteIterator`.  Example upgrade functions are `sync::Weak::upgrade` if
    /// `W` is `sync::Weak<_>`, or `rc::Weak::upgrade` if `W` is `rc::Weak<_>`.
    pub fn from_vec(vec: &'a mut Vec<W>, upgrade: F) -> Self {
        WeakAutoDeleteIterator {
            vec,
            index: 0,
            upgrade,
        }
    }
}

impl<'a, W, S, F: Fn(&W) -> Option<S>> Iterator for WeakAutoDeleteIterator<'a, W, S, F> {
    type Item = S;

    fn next(&mut self) -> Option<S> {
        while self.index < self.vec.len() {
            if let Some(item) = (self.upgrade)(&self.vec[self.index]) {
                self.index += 1;
                return Some(item);
            }
            self.vec.swap_remove(self.index);
        }
        None
    }
}


// TODO: Replace by int_roundings once that is stable
pub trait IntAlignment: Sized {
    /// Align `self` down to the closest value less or equal to `self` that is aligned to
    /// `alignment`.  Returns `None` if and only if there is no such value.
    /// `alignment` must be a power of two.
    fn align_down<T: Into<Self>>(self, alignment: T) -> Option<Self>;

    /// Align `self` up to the closest value greater or equal to `self` that is aligned to
    /// `alignment`.  Returns `None` if and only if there is no such value.
    /// `alignment` must be a power of two.
    fn align_up<T: Into<Self>>(self, alignment: T) -> Option<Self>;
}

macro_rules! impl_int_alignment_for_primitive {
    ($type:tt) => {
        impl IntAlignment for $type {
            fn align_down<T: Into<Self>>(self, alignment: T) -> Option<Self> {
                let alignment: Self = alignment.into();
                debug_assert!(alignment.is_power_of_two());

                Some(self & !(alignment - 1))
            }

            fn align_up<T: Into<Self>>(self, alignment: T) -> Option<Self> {
                let alignment: Self = alignment.into();
                debug_assert!(alignment.is_power_of_two());

                if self & (alignment - 1) == 0 {
                    return Some(self);
                }
                (self | (alignment - 1)).checked_add(1)
            }
        }
    };
}

impl_int_alignment_for_primitive!(u8);
impl_int_alignment_for_primitive!(u16);
impl_int_alignment_for_primitive!(u32);
impl_int_alignment_for_primitive!(u64);
impl_int_alignment_for_primitive!(usize);


pub trait Overlaps {
    fn overlaps(&self, other: &Self) -> bool;
}

impl<I: Ord> Overlaps for std::ops::Range<I> {
    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}


pub struct IoBuffer {
    pointer: *mut u8,
    size: usize,
    layout: Option<alloc::Layout>,
}

pub struct IoBufferRef<'a> {
    pointer: *const u8,
    size: usize,
    _lifetime: PhantomData<&'a [u8]>,
}

pub struct IoBufferMut<'a> {
    pointer: *mut u8,
    size: usize,
    _lifetime: PhantomData<&'a mut [u8]>,
}

// Blocked because of the pointer, but we want this to be usable across threads
unsafe impl Send for IoBuffer {}
unsafe impl Sync for IoBuffer {}
unsafe impl<'a> Send for IoBufferRef<'a> {}
unsafe impl<'a> Sync for IoBufferRef<'a> {}
unsafe impl<'a> Send for IoBufferMut<'a> {}
unsafe impl<'a> Sync for IoBufferMut<'a> {}

impl IoBuffer {
    /// Note that the returned buffer contains uninitialized data, which however is perfectly fine
    /// for an I/O buffer.
    pub fn new(size: usize, alignment: usize) -> BlockResult<Self> {
        let layout = alloc::Layout::from_size_align(size, alignment)?;
        Self::new_with_layout(layout)
    }

    pub fn new_with_layout(layout: alloc::Layout) -> BlockResult<Self> {
        if layout.size() == 0 {
            return Ok(IoBuffer {
                pointer: std::ptr::null_mut(),
                size: 0,
                layout: None,
            });
        }

        // We guarantee the size not to be 0 and do not care about the memory being uninitialized,
        // so this is safe
        let pointer = unsafe { alloc::System.alloc(layout) };

        if pointer.is_null() {
            return Err(format!(
                "Failed to allocate memory (size={}, alignment={})",
                layout.size(),
                layout.align()
            )
                .into());
        }

        Ok(IoBuffer {
            pointer,
            size: layout.size(),
            layout: Some(layout),
        })
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn as_ref(&self) -> IoBufferRef<'_> {
        IoBufferRef {
            pointer: self.pointer as *const u8,
            size: self.size,
            _lifetime: PhantomData,
        }
    }

    pub fn as_ref_range(&self, range: std::ops::Range<usize>) -> IoBufferRef<'_> {
        IoBufferRef::from_slice(&self.as_ref().into_slice()[range])
    }

    pub fn as_mut(&mut self) -> IoBufferMut<'_> {
        IoBufferMut {
            pointer: self.pointer,
            size: self.size,
            _lifetime: PhantomData,
        }
    }

    pub fn as_mut_range(&mut self, range: std::ops::Range<usize>) -> IoBufferMut<'_> {
        IoBufferMut::from_slice(&mut self.as_mut().into_slice()[range])
    }
}

impl Drop for IoBuffer {
    fn drop(&mut self) {
        if let Some(layout) = self.layout {
            // Safe because we have allocated this buffer using `alloc::System`
            unsafe {
                alloc::System.dealloc(self.pointer, layout);
            }
        }
    }
}

impl<'a> IoBufferRef<'a> {
    pub fn from_slice<T: Sized>(slice: &'a [T]) -> Self {
        IoBufferRef {
            pointer: slice.as_ptr() as *const u8,
            size: std::mem::size_of_val(slice),
            _lifetime: PhantomData,
        }
    }

    pub fn try_into_owned(self, alignment: usize) -> BlockResult<IoBuffer> {
        let mut new_buf = IoBuffer::new(self.size, alignment)?;
        new_buf
            .as_mut()
            .into_slice()
            .copy_from_slice(self.into_slice());
        Ok(new_buf)
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.pointer
    }

    /// References to IoBuffers must not be copied/cloned, so this consumes the object
    pub fn into_slice(self) -> &'a [u8] {
        // Alignment requirement is always met, resulting data is pure binary data
        unsafe { self.into_typed_slice::<u8>() }
    }

    /// Caller must ensure that alignment and length requirements are met and that the resulting
    /// data is valid
    pub unsafe fn into_typed_slice<T: Sized>(self) -> &'a [T] {
        // Safety ensured by the caller; we ensure that nothing outside of this buffer will be part
        // of the slice
        unsafe {
            std::slice::from_raw_parts(
                self.pointer as *const T,
                self.size / std::mem::size_of::<T>(),
            )
        }
    }

    pub fn split_at(self, mid: usize) -> (IoBufferRef<'a>, IoBufferRef<'a>) {
        let head_len = std::cmp::min(mid, self.size);

        (
            IoBufferRef {
                pointer: self.pointer,
                size: head_len,
                _lifetime: PhantomData,
            },
            IoBufferRef {
                // Safe because we have limited this to `self.size`
                pointer: unsafe { self.pointer.add(head_len) },
                size: self.size - head_len,
                _lifetime: PhantomData,
            },
        )
    }
}

impl<'a> From<IoSlice<'a>> for IoBufferRef<'a> {
    fn from(slice: IoSlice<'a>) -> Self {
        IoBufferRef {
            pointer: slice.as_ptr(),
            size: slice.len(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a> From<IoBufferRef<'a>> for IoSlice<'a> {
    fn from(buf: IoBufferRef<'a>) -> Self {
        IoSlice::new(buf.into_slice())
    }
}

impl<'a> IoBufferMut<'a> {
    pub fn from_slice<T: Sized>(slice: &'a mut [T]) -> Self {
        IoBufferMut {
            pointer: slice.as_mut_ptr() as *mut u8,
            size: std::mem::size_of_val(slice),
            _lifetime: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.pointer
    }

    /// References to IoBuffers must not be copied/cloned, so this consumes the object
    pub fn into_slice(self) -> &'a mut [u8] {
        // Alignment requirement is always meant, resulting data is pure binary data
        unsafe { self.into_typed_slice::<u8>() }
    }

    /// Caller must ensure that alignment and length requirements are met and that the resulting
    /// data is valid
    pub unsafe fn into_typed_slice<T: Sized>(self) -> &'a mut [T] {
        // Safety ensured by the caller; we ensure that nothing outside of this buffer will be part
        // of the slice
        unsafe {
            std::slice::from_raw_parts_mut(
                self.pointer as *mut T,
                self.size / std::mem::size_of::<T>(),
            )
        }
    }

    pub fn into_ref(self) -> IoBufferRef<'a> {
        IoBufferRef {
            pointer: self.pointer,
            size: self.size,
            _lifetime: PhantomData,
        }
    }

    pub fn split_at(self, mid: usize) -> (IoBufferMut<'a>, IoBufferMut<'a>) {
        let head_len = std::cmp::min(mid, self.size);

        (
            IoBufferMut {
                pointer: self.pointer,
                size: head_len,
                _lifetime: PhantomData,
            },
            IoBufferMut {
                // Safe because we have limited this to `self.size`
                pointer: unsafe { self.pointer.add(head_len) },
                size: self.size - head_len,
                _lifetime: PhantomData,
            },
        )
    }
}

impl<'a> From<IoSliceMut<'a>> for IoBufferMut<'a> {
    fn from(mut slice: IoSliceMut<'a>) -> Self {
        IoBufferMut {
            pointer: slice.as_mut_ptr(),
            size: slice.len(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a> From<IoBufferMut<'a>> for IoSliceMut<'a> {
    fn from(buf: IoBufferMut<'a>) -> Self {
        IoSliceMut::new(buf.into_slice())
    }
}

/// Collects bounce buffers that are created when enforcing minimum memory alignment requirements
/// on I/O vectors.  For read requests, dropping this object will automatically copy the data back
/// to the original guest buffers.
#[derive(Default)]
pub struct IoVectorBounceBuffers<'a> {
    /// Collection of bounce buffers; references to these are put into the re-aligned IoVector*
    /// object.
    buffers: Vec<IoBuffer>,

    /// For read requests (hence the IoSliceMut type): Collection of unaligned buffers (which have
    /// been replaced by bounce buffers in the re-aligned IoVectorMut), to which we need to return
    /// the data from the bounce buffers once the request is done (i.e., e.g., when this object is
    /// dropped).
    copy_back_into: Option<Vec<IoSliceMut<'a>>>,
}

#[macro_export]
macro_rules! impl_io_vector {
    ($type:tt, $inner_type:tt, $buffer_type:tt, $slice_type:ty, $slice_type_lifetime_b:ty) => {
        pub struct $type<'a> {
            vector: Vec<$inner_type<'a>>,
            total_size: u64,
        }

        impl<'a> $type<'a> {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn with_capacity(cap: usize) -> Self {
                $type {
                    vector: Vec::with_capacity(cap),
                    total_size: 0,
                }
            }

            /// Appends a slice to the end of the I/O vector.
            pub fn push(&mut self, slice: $slice_type) {
                debug_assert!(!slice.is_empty());
                self.total_size += slice.len() as u64;
                self.vector.push($inner_type::new(slice));
            }

            fn push_ioslice(&mut self, ioslice: $inner_type<'a>) {
                debug_assert!(!ioslice.is_empty());
                self.total_size += ioslice.len() as u64;
                self.vector.push(ioslice);
            }

            /// Basically `push`, but by taking ownership of `self` and returning it, this method
            /// allows reducing the lifetime of `self` to that of `slice`, if necessary.
            pub fn with_pushed<'b>(self, slice: $slice_type_lifetime_b) -> $type<'b>
            where
                'a: 'b,
            {
                let mut vec: $type<'b> = self;
                vec.push(slice);
                vec
            }

            /// Inserts a slice at the given `index` in the I/O vector.
            pub fn insert(&mut self, index: usize, slice: $slice_type) {
                debug_assert!(!slice.is_empty());
                self.total_size += slice.len() as u64;
                self.vector.insert(index, $inner_type::new(slice));
            }

            /// Basically `insert`, but by taking ownership of `self` and returning it, this method
            /// allows reducing the lifetime of `self` to that of `slice`, if necessary.
            pub fn with_inserted<'b>(self, index: usize, slice: $slice_type_lifetime_b) -> $type<'b>
            where
                'a: 'b,
            {
                let mut vec: $type<'b> = self;
                vec.insert(index, slice);
                vec
            }

            /// Returns the sum total length in bytes of all buffers in this vector.
            pub fn len(&self) -> u64 {
                self.total_size
            }

            /// Returns the number of buffers in this vector.
            pub fn buffer_count(&self) -> usize {
                self.vector.len()
            }

            /// Returns true if and only if this vector's length is zero, which is synonymous with
            /// whether this vector's buffer count is zero.
            pub fn is_empty(&self) -> bool {
                debug_assert!((self.total_size == 0) == self.vector.is_empty());
                self.total_size == 0
            }

            /// Appends all buffers from the given other vector to this vector.
            pub fn append(&mut self, mut other: $type<'a>) {
                self.total_size += other.total_size;
                self.vector.append(&mut other.vector);
            }

            /// Implementation for `split_at()` and `split_tail_at()`.  If `keep_head` is true,
            /// both head and tail are returned (`split_at()`).  Otherwise, the head is discarded
            /// (`split_tail_at()`).
            fn do_split_at(mut self, mid: u64, keep_head: bool) -> (Option<$type<'a>>, $type<'a>) {
                if mid >= self.total_size {
                    // Special case: Empty tail
                    return (
                        keep_head.then_some(self),
                        $type {
                            vector: Vec::new(),
                            total_size: 0,
                        },
                    );
                }

                let mut i = 0; // Current element index
                let mut offset = 0u64; // Current element offset
                let (vec_head, vec_tail) = loop {
                    if offset == mid {
                        // Clean split: `i` is fully behind `mid`, the rest is fully ahead
                        if keep_head {
                            let mut vec_head = self.vector;
                            let vec_tail = vec_head.split_off(i);
                            break (Some(vec_head), vec_tail);
                        } else {
                            break (None, self.vector.split_off(i));
                        }
                    }

                    let post_elm_offset = offset + self.vector[i].len() as u64;

                    if post_elm_offset > mid {
                        // Not so clean split: The beginning of this element was before `mid`, the end is
                        // behind it, so we must split this element between head and tail
                        let mut vec_head = self.vector;
                        let mut tail_iter = vec_head.drain(i..);

                        // This is the current element (at `i`), which must be present
                        let mid_elm = tail_iter.next().unwrap();
                        let mid_elm: $buffer_type<'a> = mid_elm.into();

                        // Each element's length is of type usize, so this must fit into usize
                        let mid_elm_head_len: usize = (mid - offset).try_into().unwrap();
                        let (mid_head, mid_tail) = mid_elm.split_at(mid_elm_head_len);

                        let mut vec_tail: Vec<$inner_type<'a>> = vec![mid_tail.into()];
                        vec_tail.extend(tail_iter);

                        if keep_head {
                            vec_head.push(mid_head.into());
                            break (Some(vec_head), vec_tail);
                        } else {
                            break (None, vec_tail);
                        }
                    }

                    offset = post_elm_offset;

                    i += 1;
                    // We know that `mid < self.total_size`, so we must encounter `mid before the end of
                    // the vector
                    assert!(i < self.vector.len());
                };

                let head = keep_head.then(|| $type {
                    vector: vec_head.unwrap(),
                    total_size: mid,
                });
                let tail = $type {
                    vector: vec_tail,
                    total_size: self.total_size - mid,
                };

                (head, tail)
            }

            /// Splits the vector into two, where the first returned vector contains the bytes in
            /// the `[0, mid)` range, and the second one covers the `[mid, self.len())` range.
            pub fn split_at(self, mid: u64) -> ($type<'a>, $type<'a>) {
                let (head, tail) = self.do_split_at(mid, true);
                (head.unwrap(), tail)
            }

            /// Like `split_at()`, but discards the head, only returning the tail.
            pub fn split_tail_at(self, mid: u64) -> $type<'a> {
                self.do_split_at(mid, false).1
            }

            /// Copy the data from `self` into `slice`.  Both must have the same length.
            pub fn copy_into_slice(&self, slice: &mut [u8]) {
                if slice.len() as u64 != self.total_size {
                    panic!("IoVector*::copy_into_slice() called on a slice of different length from the vector");
                }

                assert!(self.total_size <= usize::MAX as u64);

                let mut offset = 0usize;
                for elem in self.vector.iter() {
                    let next_offset = offset + elem.len();
                    slice[offset..next_offset].copy_from_slice(&elem[..]);
                    offset = next_offset;
                }
            }

            /// Create a new single `IoBuffer` aligned to `alignment`, which contains all data from
            /// `self.`
            pub fn try_into_owned(self, alignment: usize) -> BlockResult<IoBuffer> {
                let mut new_buf = IoBuffer::new(self.total_size.try_into()?, alignment)?;
                self.copy_into_slice(new_buf.as_mut().into_slice());
                Ok(new_buf)
            }

            /// Unsafe: `iovec` has no lifetime information.  Callers must ensure no elements in
            /// the returned slice are used beyond the lifetime `'a`.
            #[cfg(unix)]
            pub unsafe fn as_iovec(&'a self) -> &'a [libc::iovec] {
                // IoSlice and IoSliceMut are defined to have the same representation in memory as
                // libc::iovec does
                unsafe {
                    std::mem::transmute::<&'a [$inner_type<'a>], &'a [libc::iovec]>(&self.vector[..])
                }
            }

            /// Check whether `self` is aligned: Each buffer must be aligned to `mem_alignment`,
            /// and each buffer's length must be aligned to both `mem_alignment` and
            /// `req_alignment` (the I/O request offset/size alignment).
            pub fn is_aligned(&self, mem_alignment: usize, req_alignment: usize) -> bool {
                // Trivial case
                if mem_alignment == 1 && req_alignment == 1 {
                    return true;
                }

                debug_assert!(mem_alignment.is_power_of_two() && req_alignment.is_power_of_two());
                let base_align_mask = mem_alignment - 1;
                let len_align_mask = base_align_mask | (req_alignment - 1);

                self.vector.iter().all(|buf| {
                    buf.as_ptr() as usize & base_align_mask == 0 &&
                        buf.len() & len_align_mask == 0
                })
            }

            /// Consume `self`, returning an I/O vector that fulfills the given alignment
            /// requirements.  All bounce buffers that are created for this purpose are stored into
            /// `bounce_buffers` (which must have been created just for this function, i.e. must be
            /// empty).  If `copy_into` is true, the bounce buffers are initialized with data from
            /// the input vector.  If `copy_back` is true, all unaligned buffers are collected in a
            /// `Vec` (instead of discarding them) and returned as the second element of the tuple.
            /// The caller should store this `Vec` in the same `IoVectorBounceBuffers` that holds
            /// `bounce_buffers`, so that the data is copied back from the bounce buffers once the
            /// `IoVectorBounceBuffers` object is dropped.  (This function cannot operate on
            /// `IoVectorBounceBuffers` objects directly, because its `copy_back_into` field holds
            /// `IoSliceMut`s, which may not be what `$inner_type` is in this macro.)
            /// This function has the returned vector's lifetime be limited to how long the
            /// `bounce_buffers` object lives.
            fn create_aligned_buffer<'b>(
                self,
                mem_alignment: usize,
                req_alignment: usize,
                bounce_buffers: &'b mut Vec<IoBuffer>,
                copy_into: bool,
                copy_back: bool,
            ) -> BlockResult<($type<'b>, Option<Vec<$inner_type<'a>>>)>
            where
                'a: 'b,
            {
                debug_assert!(copy_into || copy_back);
                debug_assert!(mem_alignment.is_power_of_two() && req_alignment.is_power_of_two());
                let base_align_mask = mem_alignment - 1;
                let len_align_mask = base_align_mask | (req_alignment - 1);

                // First, create all bounce buffers as necessary and put them into
                // `bounce_buffers`.  Thus, `bounce_buffers` no longer needs to be mutable after
                // this loop, which allows us to take `$inner_type<b>` references from those
                // buffers while they are in the `Vec<IoBuffer>`.

                let mut unaligned_length_collection: Option<usize> = None;
                for buffer in &self.vector {
                    let base = buffer.as_ptr() as usize;
                    let len = buffer.len();

                    if base & base_align_mask != 0 || len & len_align_mask != 0 || unaligned_length_collection.is_some() {
                        let unaligned_len =
                            unaligned_length_collection
                            .unwrap_or(0)
                            .checked_add(len)
                            .ok_or("I/O vector length overflow")?;
                        unaligned_length_collection = Some(unaligned_len);

                        if unaligned_len & len_align_mask == 0 {
                            bounce_buffers.push(IoBuffer::new(unaligned_len, mem_alignment)?);
                            unaligned_length_collection = None;
                        }
                    }
                }

                // Second, create the I/O vector that is returned: Interleave already aligned
                // vector buffers with references to the newly created buffers (which have the
                // proper lifetime `'b`), and copy data into those new buffers if `copy_into`.  If
                // `copy_back`, collect the replaced buffers in `copy_back_vector`.

                let mut realigned_vector = Vec::<$inner_type<'b>>::new();
                let mut unaligned_collection: Option<Self> = None;
                let mut buffer_iter = bounce_buffers.iter_mut();
                let mut copy_back_vector = copy_back.then(|| Vec::<$inner_type<'a>>::new());

                for buffer in self.vector {
                    let base = buffer.as_ptr() as usize;
                    let len = buffer.len();

                    if base & base_align_mask != 0 || len & len_align_mask != 0 || unaligned_collection.is_some() {
                        let collection = unaligned_collection.get_or_insert_with(|| Self::new());
                        collection.push_ioslice(buffer);

                        let unaligned_len: usize = collection.len().try_into()?;
                        if unaligned_len & len_align_mask == 0 {
                            let new_buf: &'b mut IoBuffer = buffer_iter.next().unwrap();
                            if copy_into {
                                collection.copy_into_slice(new_buf.as_mut().into_slice());
                            }

                            // Drop the collection
                            let mut collection = unaligned_collection.take().unwrap();
                            if let Some(copy_back_vector) = copy_back_vector.as_mut() {
                                copy_back_vector.append(&mut collection.vector);
                            }

                            // Get a reference from `bounce_buffers` to ensure the lifetime
                            realigned_vector.push($inner_type::new(new_buf.as_mut().into_slice()));
                        }
                    } else {
                        realigned_vector.push(buffer);
                    }
                }

                Ok((
                    $type {
                        vector: realigned_vector,
                        total_size: self.total_size,
                    },
                    copy_back_vector,
                ))
            }

            /// Returns the internal vector of `IoSlice` objects.
            pub fn into_inner(self) -> Vec<$inner_type<'a>> {
                self.vector
            }
        }

        impl<'a> From<Vec<$inner_type<'a>>> for $type<'a> {
            fn from(vector: Vec<$inner_type<'a>>) -> Self {
                let total_size = vector
                    .iter()
                    .map(|e| e.len())
                    .fold(0u64, |sum, e| sum + e as u64);

                $type { vector, total_size }
            }
        }

        impl<'a> From<$buffer_type<'a>> for $type<'a> {
            fn from(buffer: $buffer_type<'a>) -> Self {
                let total_size = buffer.len() as u64;
                if total_size > 0 {
                    $type {
                        vector: vec![buffer.into()],
                        total_size,
                    }
                } else {
                    $type {
                        vector: Vec::new(),
                        total_size: 0,
                    }
                }
            }
        }

        impl<'a> From<$slice_type> for $type<'a> {
            fn from(slice: $slice_type) -> Self {
                let total_size = slice.len() as u64;
                if total_size > 0 {
                    $type {
                        vector: vec![$inner_type::new(slice)],
                        total_size,
                    }
                } else {
                    $type {
                        vector: Vec::new(),
                        total_size: 0,
                    }
                }
            }
        }

        impl<'a> Default for $type<'a> {
            fn default() -> Self {
                $type {
                    vector: Vec::new(),
                    total_size: 0,
                }
            }
        }
    };
}

impl_io_vector!(IoVector, IoSlice, IoBufferRef, &'a [u8], &'b [u8]);
impl_io_vector!(
    IoVectorMut,
    IoSliceMut,
    IoBufferMut,
    &'a mut [u8],
    &'b mut [u8]
);

impl<'a> IoVector<'a> {
    /// Ensure that all buffers in the vector adhere to the given alignment.  Buffers'
    /// addresses must be aligned to `mem_alignment`, and their lengths must be aligned to
    /// both `mem_alignment` and `req_alignment`.
    /// To align everything, bounce buffers are created and filled with data from the
    /// buffers in the vector (which is why this is only for writes).  These bounce buffers
    /// are stored in `bounce_buffers`, and the lifetime `'b` ensures this object will
    /// outlive the returned new vector.
    /// `bounce_buffers` must have been created specifically for this single function call through
    /// `IoVectorBounceBuffers::default()`.
    pub fn enforce_alignment_for_write<'b>(
        self,
        mem_alignment: usize,
        req_alignment: usize,
        bounce_buffers: &'b mut IoVectorBounceBuffers<'static>,
    ) -> BlockResult<IoVector<'b>>
    where
        'a: 'b,
    {
        debug_assert!(bounce_buffers.is_empty());

        let (aligned, copy_back_buffers) = self.create_aligned_buffer(
            mem_alignment,
            req_alignment,
            &mut bounce_buffers.buffers,
            true,
            false,
        )?;
        debug_assert!(copy_back_buffers.is_none());
        Ok(aligned)
    }
}

impl<'a> IoVectorMut<'a> {
    /// Fill all buffers in the vector with the given byte pattern.
    pub fn fill(&mut self, value: u8) {
        for slice in self.vector.iter_mut() {
            slice.fill(value);
        }
    }

    /// Copy data from `slice` into the buffers in this vector.  The vector and the slice must have
    /// the same total length.
    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        if slice.len() as u64 != self.total_size {
            panic!("IoVectorMut::copy_from_slice() called on a slice of different length from the vector");
        }

        assert!(self.total_size <= usize::MAX as u64);

        let mut offset = 0usize;
        for elem in self.vector.iter_mut() {
            let next_offset = offset + elem.len();
            elem.copy_from_slice(&slice[offset..next_offset]);
            offset = next_offset;
        }
    }

    #[cfg(feature = "vhost-user-blk")] // Used only by vhost-user-blk
    pub fn into_const(self) -> IoVector<'a> {
        // Both `IoSliceMut` and `IoSlice` guarantee to be ABI compatible with `IoSliceMut`, so
        // they must also be compatible with each other
        let vector =
            unsafe { std::mem::transmute::<Vec<IoSliceMut<'a>>, Vec<IoSlice<'a>>>(self.vector) };

        IoVector {
            vector,
            total_size: self.total_size,
        }
    }

    /// Ensure that all buffers in the vector adhere to the given alignment.  Buffers'
    /// addresses must be aligned to `mem_alignment`, and their lengths must be aligned to
    /// both `mem_alignment` and `req_alignment`.
    /// To align everything, bounce buffers are created without initializing them (which is
    /// why this is only for reads).  These bounce buffers are stored in `bounce_buffers`,
    /// and the lifetime `'b` ensures this object will outlive the returned new vector.
    /// When `bounce_buffers` is dropped, the data in those bounce buffers (filled by the read
    /// operation) will automatically be copied back into the original guest buffers.
    /// `bounce_buffers` must have been created specifically for this single function call through
    /// `IoVectorBounceBuffers::default()`.
    pub fn enforce_alignment_for_read<'b>(
        self,
        mem_alignment: usize,
        req_alignment: usize,
        bounce_buffers: &'b mut IoVectorBounceBuffers<'a>,
    ) -> BlockResult<IoVectorMut<'b>>
    where
        'a: 'b,
    {
        debug_assert!(bounce_buffers.is_empty());

        let (aligned, copy_back_buffers) = self.create_aligned_buffer(
            mem_alignment,
            req_alignment,
            &mut bounce_buffers.buffers,
            false,
            true,
        )?;
        bounce_buffers.copy_back_into = copy_back_buffers;
        Ok(aligned)
    }
}

impl IoVectorBounceBuffers<'_> {
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty() && self.copy_back_into.is_none()
    }
}

impl Drop for IoVectorBounceBuffers<'_> {
    /// If the data in the bounce buffers is to be copied back into the original guest buffers (for
    /// read operations), do so when the bounce buffers are dropped.
    fn drop(&mut self) {
        if let Some(copy_back_into) = self.copy_back_into.take() {
            let input_buffer_count = self.buffers.len();
            let mut input_i = 0;
            let mut input_offset = 0;

            for mut target_buffer in copy_back_into {
                let next_input_offset = input_offset + target_buffer.len();
                let input_buffer = self.buffers[input_i].as_ref().into_slice();
                target_buffer.copy_from_slice(&input_buffer[input_offset..next_input_offset]);
                input_offset = next_input_offset;

                debug_assert!(input_offset <= input_buffer.len());
                if input_offset == input_buffer.len() {
                    input_i += 1;
                    input_offset = 0;
                }
            }

            debug_assert!(input_i == input_buffer_count);
        }
    }
}


/// Wrap an object of type `T` such that when it is dropped, it will be sent to a
/// `oneshot::Receiver<T>`, if any was registered.  This allows running the receiver in an async
/// context to run async drop code.
pub struct SendOnDrop<T> {
    inner: Option<T>,
    notifier: Mutex<Option<oneshot::Sender<T>>>,
}

impl<T> SendOnDrop<T> {
    /// Wrap the object in `SendOnDrop`, but without installing an on-drop receiver yet.  Dropping
    /// the object will just drop it.
    pub fn new(object: T) -> Self {
        SendOnDrop {
            inner: Some(object),
            notifier: Mutex::new(None),
        }
    }

    /// Install a receiver to retrieve the object when the wrapper is dropped.  Only one receiver
    /// can be installed at a time, so if there already is one, this will return an error.
    pub fn make_receiver(&self) -> BlockResult<oneshot::Receiver<T>> {
        let (sender, receiver) = oneshot::channel();

        let mut notifier = self.notifier.lock().unwrap();
        if notifier.is_some() {
            return Err(format!(
                "Tried to add a receiver to SendOnDrop<{}>, which already has one",
                std::any::type_name::<T>()
            )
                .into());
        }
        *notifier = Some(sender);
        Ok(receiver)
    }

    /// Install a receiver on an `Arc<SendOnDrop<T>>` while consuming the `Arc<_>`.  If there is an
    /// error because there already is a receiver installed, the `Arc<_>` is returned again.
    pub fn into_receiver(self: Arc<Self>) -> Result<oneshot::Receiver<T>, Arc<Self>> {
        self.make_receiver().map_err(|_| self)
    }

    /// Try to retrieve the wrapped value.  This will fail if there already is a receiver
    /// installed, because the receiver is guaranteed to get it.
    pub fn try_unwrap(mut self) -> Result<T, Self> {
        if self.notifier.get_mut().unwrap().is_some() {
            Err(self)
        } else {
            Ok(self.inner.take().unwrap())
        }
    }
}

impl<T: Default> Default for SendOnDrop<T> {
    fn default() -> Self {
        SendOnDrop::new(<T as Default>::default())
    }
}

impl<T> Drop for SendOnDrop<T> {
    fn drop(&mut self) {
        // If `self.inner` is `None`, the object was already taken via `try_unwrap()`.
        if let Some(inner) = self.inner.take() {
            if let Some(sender) = self.notifier.get_mut().unwrap().take() {
                let _: Result<(), _> = sender.send(inner);
            }
        }
    }
}

impl<T> std::ops::Deref for SendOnDrop<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.inner.as_ref().unwrap()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for SendOnDrop<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <T as std::fmt::Debug>::fmt(self.inner.as_ref().unwrap(), f)
    }
}


/// Allows joining an arbitrary number of futures.  When awaited, returns `Ok(())` on success, or
/// the first error encountered.
pub struct FutureJoin<'a> {
    /// If there's just a single future, store it here for a quicker path
    single: Option<BlockFutureResult<'a, ()>>,
    vec: Option<Vec<BlockFutureResult<'a, ()>>>,
}

impl<'a> FutureJoin<'a> {
    pub fn new() -> Self {
        FutureJoin {
            single: None,
            vec: None,
        }
    }

    /// Add a future to the mix
    pub fn push(&mut self, fut: BlockFutureResult<'a, ()>) {
        if let Some(vec) = self.vec.as_mut() {
            vec.push(fut);
        } else if let Some(single) = self.single.take() {
            self.vec = Some(vec![single, fut]);
        } else {
            self.single = Some(fut);
        }
    }
}

impl<'a> Future for FutureJoin<'a> {
    type Output = BlockResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(single) = self.single.as_mut() {
            Future::poll(single.as_mut(), cx)
        } else if let Some(vec) = self.vec.as_mut() {
            let mut i = 0;
            while i < vec.len() {
                match Future::poll(vec[i].as_mut(), cx) {
                    Poll::Ready(Ok(())) => {
                        vec.swap_remove(i);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => i += 1,
                }
            }
            if i == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}


#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// Similar to `Option<T>`, but differentiates between `NotSpecified` (use implicit behavior) and
/// `Null` (explicitly no value).  For serialization, parent objects must ensure that
/// `Tristate::NotSpecified` is not serialized (i.e. via
/// `#[serde(skip_serializing_if = "Tristate::skip_serializing")]`).
pub enum Tristate<T> {
    #[default]
    NotSpecified,
    Null,
    Some(T),
}

struct TristateVisitor<T>(PhantomData<T>);

impl<T> Tristate<T> {
    pub fn skip_serializing(&self) -> bool {
        matches!(self, Tristate::NotSpecified)
    }
}

impl<'de, T: Deserialize<'de>> de::Visitor<'de> for TristateVisitor<T> {
    type Value = Tristate<T>;

    fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "nothing (implicit behavior), null (explicitly nothing), or a value of type {}",
            std::any::type_name::<T>()
        )
    }

    /// Explicitly nothing
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Tristate::Null)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let obj = T::deserialize(serde::de::value::StrDeserializer::new(v))?;
        Ok(Tristate::Some(obj))
    }

    fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        let obj = T::deserialize(de::value::MapAccessDeserializer::new(map))?;
        Ok(Tristate::Some(obj))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Tristate<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TristateVisitor(PhantomData::<T> {}))
    }
}

impl<T: Serialize> Serialize for Tristate<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Tristate::NotSpecified => panic!("Cannot directly serialize Tristate::NotSpecified -- parent object must skip serialization"),
            Tristate::Null => serializer.serialize_unit(),
            Tristate::Some(obj) => serializer.serialize_some(obj),
        }
    }
}
