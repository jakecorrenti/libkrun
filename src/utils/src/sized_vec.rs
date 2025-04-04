// https://github.com/cloud-hypervisor/cloud-hypervisor/blob/f811e36443615b1da5fa8f98b80e64ae3933eaf6/hypervisor/src/lib.rs#L97
// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// https://github.com/cloud-hypervisor/cloud-hypervisor/blob/f811e36443615b1da5fa8f98b80e64ae3933eaf6/hypervisor/src/lib.rs#L120
use std::mem::size_of;
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}
