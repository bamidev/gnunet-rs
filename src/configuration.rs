use gnunet_sys::*;

use std::ptr;



pub struct Handle {
	pub (in crate) inner: *mut GNUNET_CONFIGURATION_Handle
}



impl Handle {

	pub fn create() -> Self {
		let inner = unsafe { GNUNET_CONFIGURATION_create() };
		assert!( inner != ptr::null_mut(), "inner handle cannot be null" );

		Self {
			inner
		}
	}

	pub fn from_inner( inner: *mut GNUNET_CONFIGURATION_Handle ) -> Self {
		Self {
			inner
		}
	}
}