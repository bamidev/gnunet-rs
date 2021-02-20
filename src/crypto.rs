use std::{
	ffi::*,
	mem::MaybeUninit
};

use gnunet_sys::*;



pub struct PeerIdentity {
	pub (in crate) inner: GNUNET_PeerIdentity
}



impl PeerIdentity {

	pub fn from_inner( inner: GNUNET_PeerIdentity ) -> Self {
		Self { inner }
	}

	/// Constructs a `PeerIdentity` from a formatted public key string.
	pub fn from_string( string: &str ) -> Self {
		let cstring = CString::new(string).expect("null character in string");

		let mut i: GNUNET_CRYPTO_EddsaPublicKey = unsafe { MaybeUninit::uninit().assume_init() };

		let result = unsafe { GNUNET_CRYPTO_eddsa_public_key_from_string( cstring.as_ptr(), string.len() as _, &mut i as _ ) };
		assert!( result == 0, "invalid result from GNUNET_CRYPTO_eddsa_public_key_from_string" );

		Self {
			inner: GNUNET_PeerIdentity {
				public_key: i
			}
		}
	}

	pub fn to_string( &self ) -> String {

		let string = unsafe { CStr::from_ptr( GNUNET_CRYPTO_eddsa_public_key_to_string( &self.inner.public_key as _ ) ) };

		string.to_string_lossy().into_owned()
	}
}