use gnunet_sys::*;

use std::ptr;



#[derive(Clone, Copy)]
pub struct Handle ( pub (in crate) *const GNUNET_CONFIGURATION_Handle );

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}



impl Handle {

	pub fn create() -> Self {
		let inner = unsafe { GNUNET_CONFIGURATION_create() };
		assert!( inner != ptr::null_mut(), "inner handle cannot be null" );

		Self (
			inner
		)
	}

	pub fn from_inner( inner: *const GNUNET_CONFIGURATION_Handle ) -> Self {
		Self (
			inner
		)
	}
}

impl Default for Handle {

	fn default() -> Self {
		Self ( ptr::null() )
	}
}