use std::{
	convert::TryFrom,
	ffi::*,
	fmt,
	os::raw::*,
	mem::MaybeUninit
};

use gnunet_sys::*;
use serde::{*};



#[derive(Clone)]
pub struct HashCode ( pub(in crate) GNUNET_HashCode );
pub struct HashCodeVisitor;

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
	/// Returns None if the given string was not properly encoded or does not decode to a proper hash code.
	pub fn from_string( _string: &str ) -> Option<Self> {

		let mut hash = Self::new();

		let result = unsafe {

			// `GNUNET_CRYPTO_hash_from_string2`, at some point still calls `strlen` on its first argument.
			// Therefore, we need to make sure it is an actual null-terminated string.
			let string = CString::new(_string).unwrap();

			GNUNET_CRYPTO_hash_from_string2( string.as_ptr(), _string.len() as _, &mut hash.0 as _ )
		};

		if result != GNUNET_GenericReturnValue_GNUNET_SYSERR {
			return None;
		}

		Some( hash )
	}

	pub fn generate( data: &[u8] ) -> Self {
		let mut hash = Self::new();

		unsafe { GNUNET_CRYPTO_hash( data.as_ptr() as _, data.len() as _, &mut hash.0 as _ ) };

		hash
	}

	pub fn raw_data<'a>( &'a self ) -> &'a [u32; 16] {
		&self.0.bits
	}

	pub fn raw_data_mut<'a>( &'a mut self ) -> &'a mut [u32; 16] {
		&mut self.0.bits
	}

	pub fn to_string( &self ) -> String {

		unsafe {
			let mut encoded: GNUNET_CRYPTO_HashAsciiEncoded = MaybeUninit::uninit().assume_init();

			GNUNET_CRYPTO_hash_to_enc( &self.0 as _, &mut encoded as _ );

			CStr::from_ptr( &encoded.encoding as *const u8 as *const c_char )
				.to_str().unwrap().to_owned()
		}
	}
}

impl Serialize for HashCode {

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where
		S: Serializer
	{
		let inner_data = self.raw_data();
		let mut buffer = [0u8; 64];

		// Convert an array of u32 to an array of u8
		for i in 0..16 {
			let le_bytes = inner_data[i].to_le_bytes();

			// Copy bytes into buffer
			for j in 0..4 {
				buffer[i*4 + j] = le_bytes[j];
			}
		}

		serializer.serialize_bytes( &buffer )
	}
}

impl<'de> Deserialize<'de> for HashCode {
	fn deserialize<D>(deserializer: D) -> Result<HashCode, D::Error> where
		D: Deserializer<'de>
	{
		deserializer.deserialize_bytes( HashCodeVisitor )
	}
}

impl<'de> de::Visitor<'de> for HashCodeVisitor {

	type Value = HashCode;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a 256-bit long byte-string")
	}

	fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E> where
		E: de::Error
	{
		if bytes.len() < 64 {
			return Err( de::Error::custom("not enough bytes") );
		}

		// Not initializing here is safe because the `HashCode` struct only has an underlying array of u32, and we update each u32 anyway.
		let mut result: HashCode = unsafe { MaybeUninit::uninit().assume_init() };

		// Copy all bytes into array of u32's
		for i in 0..16 {
			let begin = i*4;	let end = begin + 4;
			let int = u32::from_le_bytes( <[u8; 4]>::try_from( &bytes[begin..end] ).unwrap() );
			result.raw_data_mut()[i] = int;
		}

		Ok( result )
	}
}