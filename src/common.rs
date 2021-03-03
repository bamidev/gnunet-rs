use std::{mem, slice};



pub(in crate) fn as_bytes<'a,T>( data: &'a T ) -> &'a [u8] {
	unsafe { slice::from_raw_parts( data as *const T as _, mem::size_of::<T>() ) }
}

pub(in crate) fn as_bytes_mut<'a,T>( data: &'a mut T ) -> &'a mut [u8] {
	unsafe { slice::from_raw_parts_mut( data as *mut T as _, mem::size_of::<T>() ) }
}