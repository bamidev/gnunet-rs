use crate::configuration;
use crate::crypto::PeerIdentity;

use std::{
	ffi::{CStr, CString},
	fmt,
	ptr,
	os::raw::*
};

use gnunet_sys::*;



pub struct Handle {
	inner: *mut GNUNET_PEERSTORE_Handle
}

pub struct IterateError {
	msg: *const c_char
}

pub struct PeerIterator {
	ps: *mut GNUNET_PEERSTORE_Handle
}

pub struct Record {
	inner: *const GNUNET_PEERSTORE_Record
}

pub struct StoreContext {
	inner: *mut GNUNET_PEERSTORE_StoreContext
}

pub type StoreOption = GNUNET_PEERSTORE_StoreOption;

pub const STORE_OPTION_MULTIPLE: StoreOption = 0;
pub const STORE_OPTION_REPLACE: StoreOption = 1;



impl Handle {

	/// Connects to the peerstore service and returns this handle.
	pub fn connect( config: &configuration::Handle ) -> Self {
		let inner = unsafe { GNUNET_PEERSTORE_connect( config.inner ) };
		assert!( inner != ptr::null_mut(), "unable to connect peerstore" );

		Self {
			inner
		}
	}

	pub fn disconnect( self, sync_first: bool ) {
		unsafe { GNUNET_PEERSTORE_disconnect( self.inner, if sync_first {1} else {0} ) };
	}

	pub fn iterate<C>( &self, subsystem: &str, key: Option<&str>, on_peer: C ) where
		C: FnMut(Result<Record, IterateError>)
	{
		let csubsystem = CString::new(subsystem).expect("null character in subsystem");
		let ckey = match key {
			Some(p) => p.as_ptr() as *const c_char,
			None => ptr::null_mut()
		};
		
		let callback_data = Box::into_raw( Box::new( on_peer ) );

		unsafe { GNUNET_PEERSTORE_iterate( self.inner, csubsystem.as_ptr(), ptr::null(), ckey, Some(ffi_iterate_callback::<C>), callback_data as _ ) };
	}

	pub fn store<H>( &self, subsystem: &str, peer: &PeerIdentity, key: &str, value: Vec<u8>, expiry: u64, options: StoreOption, on_complete: H ) -> StoreContext where
		H: FnOnce(bool)
	{
		let csubsystem = CString::new(subsystem).expect("null character in subsystem");
		let ckey = CString::new(key).expect("null character in key");

		let expiry_struct = GNUNET_TIME_Absolute {
			abs_value_us: expiry
		};

		let cls = Box::into_raw( Box::new( on_complete ) );

		let store_ctx_inner = unsafe { GNUNET_PEERSTORE_store( self.inner, csubsystem.as_ptr(), &peer.inner, ckey.as_ptr(), value.as_ptr() as _, value.len() as _, expiry_struct, options, Some( ffi_on_complete::<H> ), cls as _ ) };

		StoreContext {
			inner: store_ctx_inner
		}
	}

	// pub async fn store( ... )
}

impl fmt::Display for IterateError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let cstr = unsafe { CStr::from_ptr( self.msg ) };
		write!(f, "{}", cstr.to_string_lossy().as_ref() )
	}
}

impl Record {

	pub fn peer( &self ) -> PeerIdentity {
		PeerIdentity::from_inner( unsafe { (*self.inner).peer } )
	}

	
}

impl StoreContext {

	pub fn cancel( &mut self ) {
		unsafe { GNUNET_PEERSTORE_store_cancel( self.inner ) }
	}
}



unsafe extern "C" fn ffi_iterate_callback<C>( data: *mut c_void, record: *const GNUNET_PEERSTORE_Record, error_msg: *const c_char ) where
	C: FnMut(Result<Record,IterateError>)
{
	let mut callback: Box<C> = Box::from_raw( data as _ );
	
	if record != ptr::null() {
		callback( Ok( Record { inner: record } ) );
	}
	else if error_msg != ptr::null() {
		callback( Err( IterateError { msg: error_msg } ) );
	}
}

unsafe extern "C" fn ffi_on_complete<H>( data: *mut c_void, success: c_int ) where H: FnOnce(bool) {

	let on_complete: Box<H> = Box::from_raw( data as _ );
	on_complete( success != 0 );
}