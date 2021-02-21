use std::{
	ffi::*,
	mem::MaybeUninit
};

use gnunet_sys::*;



pub struct HashCode ( pub(in crate) GNUNET_HashCode );

pub struct PeerIdentity (
	pub (in crate) GNUNET_PeerIdentity
);



impl PeerIdentity {

	pub fn from_inner( inner: GNUNET_PeerIdentity ) -> Self {
		Self ( inner )
	}

	/// Constructs a `PeerIdentity` from a formatted public key string.
	pub fn from_string( string: &str ) -> Self {
		let cstring = CString::new(string).expect("null character in string");

		let mut i: GNUNET_CRYPTO_EddsaPublicKey = unsafe { MaybeUninit::uninit().assume_init() };

		let result = unsafe { GNUNET_CRYPTO_eddsa_public_key_from_string( cstring.as_ptr(), string.len() as _, &mut i as _ ) };
		assert!( result == 0, "invalid result from GNUNET_CRYPTO_eddsa_public_key_from_string" );

		Self (
			GNUNET_PeerIdentity {
				public_key: i
			}
		)
	}

	pub fn to_string( &self ) -> String {

		let string = unsafe { CStr::from_ptr( GNUNET_CRYPTO_eddsa_public_key_to_string( &self.0.public_key as _ ) ) };

		string.to_string_lossy().into_owned()
	}
}



impl HashCode {

	/// Creates an uninitialized hash code.
	pub fn new() -> Self {
		unsafe {
			MaybeUninit::uninit().assume_init()
		}
	}

	/// Creates a `HashCode` from its Crockford Base32hex encoded string.
	pub fn from_string( _string: &str ) -> Self {

		let mut hash = Self::new();

		let result = unsafe {

			// `GNUNET_CRYPTO_hash_from_string2`, at some point still calls `strlen` on its first argument.
			// Therefore, we need to make sure it is an actual null-terminated string.
			let string = CString::new(_string).unwrap();

			GNUNET_CRYPTO_hash_from_string2( string.as_ptr(), _string.len() as _, &mut hash.0 as _ )
		};

		assert!( result != GNUNET_GenericReturnValue_GNUNET_SYSERR, "hash result does not have proper Crockford Base32hex encoding" );

		hash
	}

	pub fn generate( data: &[u8] ) -> Self {
		let mut hash = Self::new();

		unsafe { GNUNET_CRYPTO_hash( data.as_ptr() as _, data.len() as _, &mut hash.0 as _ ) };

		hash
	}
}