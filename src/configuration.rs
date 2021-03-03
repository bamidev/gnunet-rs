use gnunet_sys::*;

use std::{
	ffi::*,
	mem::MaybeUninit,
	os::raw::*,
	path::*,
	ptr
};



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

	pub fn get_value_filename( &self, section: &str, option: &str ) -> PathBuf {

		let csection = CString::new(section).expect("null character in `section`");
		let coption = CString::new(option).expect("null character in `option`");
		let mut cvalue: *mut c_char = unsafe { MaybeUninit::uninit().assume_init() };

		unsafe {
			GNUNET_CONFIGURATION_get_value_filename( self.0, csection.as_ptr(), coption.as_ptr(), &mut cvalue as _ );

			let value = CStr::from_ptr( cvalue ).to_str().expect("non utf-8 character in value");
			eprintln!("PATH: {}", &value);
			let path: PathBuf = value.into();

			GNUNET_free( cvalue as _ ); path
		}
	}

	pub fn get_value_string( &self, section: &str, option: &str ) -> String {

		let csection = CString::new(section).expect("null character in `section`");
		let coption = CString::new(option).expect("null character in `option`");
		let mut cvalue: *mut c_char = unsafe { MaybeUninit::uninit().assume_init() };

		unsafe {
			GNUNET_CONFIGURATION_get_value_string( self.0, csection.as_ptr(), coption.as_ptr(), &mut cvalue as _ );

			let value = CStr::from_ptr( cvalue ).to_str().expect("non utf-8 character in value").to_owned();

			GNUNET_free( cvalue as _ ); value
		}
	}
}

impl Default for Handle {

	fn default() -> Self {
		let inner = unsafe { GNUNET_CONFIGURATION_default() };
		Self ( inner )
	}
}