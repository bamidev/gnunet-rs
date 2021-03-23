use gnunet_sys::*;
use async_std::prelude::*;
use serde::{*, ser::*};

use std::{
	collections::HashMap,
	ffi::*,
	fmt,
	io,
	mem::{self, MaybeUninit}
};

use crate::{
	common::*,
	error,
	gnunet,
	decl_service, impl_service
};



decl_service!( Handle );
impl_service!( Handle );

pub struct Ego {
	pub name: String,
	pub private_key: PrivateKey
}

#[derive(Clone)]
pub struct PrivateKey ( pub(in crate) GNUNET_IDENTITY_PrivateKey );

#[derive(Clone)]
pub struct PublicKey ( pub(in crate) GNUNET_IDENTITY_PublicKey );
struct PublicKeyVisitor;

pub enum KeyType {
	Ecdsa = 0x00001000, // = htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDSA )
	Eddsa = 0x14001000  // = htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDDA )
}
const KEYTYPE_ECDSA: GNUNET_IDENTITY_KeyType = 0x00000100;
const KEYTYPE_EDDSA: GNUNET_IDENTITY_KeyType = 0x14000100;

#[derive(Clone)]
pub struct Signature ( pub(in crate) GNUNET_IDENTITY_Signature );
struct SignatureVisitor;





impl Ego {

	/// Extracts the public key from the private key of this ego.
	pub fn extract_public_key( &self ) -> Option<PublicKey> {
		self.private_key.extract_public()
	}

	pub fn new( name: String, private_key: PrivateKey ) -> Self {
		Self {
			name,
			private_key
		}
	}
}

impl Handle {

	pub async fn connect( gnunet: gnunet::Handle ) -> error::Result<Self> {

		let service = gnunet.service("identity").connect().await?;		

		Ok( service.into() )
	}

	/// Returns all identities as names mapped to private keys.
	pub async fn list( &mut self ) -> io::Result<HashMap<String, PrivateKey>> {

		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_START as _, 4u16 ).await?;
		self.0.flush().await?;

		let mut egos = HashMap::new();

		loop {
			let header = self.0.read_header().await?;
			assert!(header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE as u16, "invalid message type detected");

			let (name, private_key, end_of_list) = self.read_update( header.size - 4 ).await?;
			egos.insert( name, private_key );

			if end_of_list {
				break;
			}
		}

		Ok(egos)
	}

	/// Looks up an ego by name.
	/// If found, returns its private key.
	pub async fn lookup( &mut self, name: &str ) -> error::Result<Option<PrivateKey>> {
		
		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP as _, (4 + name.len() + 1) as _ ).await?;
		self.0.write_str_zt( name ).await?;
		self.0.flush().await?;
		
		let header = self.0.read_header().await?;
		if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _ {
			let result = self.0.read_result( header.size ).await;
			
			match result {
				Ok(()) => Err( io::Error::from( io::ErrorKind::InvalidData ).into() ),
				Err(e) => {
					match e {
						error::Error::Result(r) => {
							if r.code == 99999 {
								Ok( None )
							} else {
								Err(r.into())
							}
						},
						other => Err(other)
					}
				}
			}
		}
		else if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE as _ {
			
			let (_, private_key, _) = self.read_update( header.size - 4 ).await?;
			Ok( Some( private_key ) )
		}
		else {
			panic!("unexpected message received from identity service");
		}
	}

	/// Create a new ego with the given name.
	/// 
	/// # Arguments
	/// * `name` - desired name.
	/// * `private_key` - private key for this ego.
	/// 
	/// # Returns
	/// A handle to abort the operation
	pub async fn create( &mut self, name: &str, private_key: PrivateKey ) -> error::Result<bool> {

		// Send request
		//let size = 4 + mem::size_of::<CreateRequestMessage>() + name.len() + 1;
		let size = 4 + 2 + 2 + mem::size_of::<PrivateKey>() + name.len() + 1;
		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_CREATE as _, size as _ ).await?;
		let name_length: u16 = name.len() as u16 + 1;
		self.0.write_u16( name_length ).await?;
		self.0.write_u16( 0 ).await?;
		self.0.write( as_bytes( &private_key.0 ) ).await?;
		self.0.write_str_zt( name ).await?;
		self.0.flush().await?;

		// Receive response
		let header = self.0.read_header().await?;
		assert!(header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _, "unrecognized response message received");
		
		let result = self.0.read_result( header.size ).await;

		// Transform gnunet error 1 into false, because it indicates the ego already existed.
		match result {
			Ok(()) => Ok(true),
			Err(e) => {
				match e {
					error::Error::Result(r) => {
						if r.code == 1 {
							Ok(false)
						} else {
							Err(r.into())
						}
					},
					other => Err(other)
				}
			}
		}
	}

	/// Gets the default ego for the given service.
	pub async fn get_default( &mut self, service: &str ) -> error::Result<Option<Ego>> {

		// Send request
		let size = mem::size_of::<GNUNET_MessageHeader>() + 2 + 2 + service.len() + 1;
		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT as _, size as _ ).await?;
		self.0.write_u16( service.len() as _ ).await?;
		self.0.write_u16(0).await?;
		self.0.write_str_zt( service ).await?;

		// Receive response
		let header = self.0.read_header().await?;

		if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE as _ {
			let (name, private_key, _) = self.read_update( header.size - 4 ).await?;
			return Ok(Some(Ego::new(name, private_key)));
		}

		if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _ {
			self.0.read_result( header.size ).await?;
			panic!("succesful result received");
		}

		panic!("invalid response message detected");
	}

	async fn read_update( &mut self, max_length: u16 ) -> io::Result<(String, PrivateKey, bool)> {

		let name_len = self.0.read_u16().await?;
		let end_of_list = self.0.read_u16().await?;
		let private_key: GNUNET_IDENTITY_PrivateKey = self.0.read_as_bytes().await?;

		// Due to a bug it might happen that the zero termination character is omitted.
		// We can handle it nevertheless.
		let name = if max_length < (2 + 2 + mem::size_of::<GNUNET_IDENTITY_PrivateKey>() + name_len as usize + 1) as _ {
			self.0.read_str( name_len ).await?
		}
		else {
			self.0.read_str_zt( name_len ).await?
		};

		Ok((name, PrivateKey ( private_key ), end_of_list != GNUNET_GenericReturnValue_GNUNET_NO as _))
	}

	// Sets the default `ego` for the given `service`.
	pub async fn set_default( &mut self, service: &str, ego: &Ego ) -> error::Result<()> {

		// Send request
		let size = mem::size_of::<GNUNET_MessageHeader>() + 2 + 2 + mem::size_of::<GNUNET_IDENTITY_PrivateKey>() + service.len() + 1;
		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT as _, size as _ ).await?;
		self.0.write_u16( service.len() as _ ).await?;
		self.0.write_u16(0).await?;
		self.0.write_as_bytes( &ego.private_key.0 ).await?;
		self.0.write_str_zt( service ).await?;

		// Receive request
		let header = self.0.read_header().await?;
		assert!(header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _, "invalid response message received");
		self.0.read_result( header.size ).await
	}
}

impl PrivateKey {

	// Extracts the public key that belongs to the this private key.
	pub fn extract_public( &self ) -> Option<PublicKey> {
		unsafe {
			let mut public_key: PublicKey = MaybeUninit::uninit().assume_init();
			
			let result = GNUNET_IDENTITY_key_get_public( &self.0 as _, &mut public_key.0 );
			if result == GNUNET_GenericReturnValue_GNUNET_SYSERR {
				return None;
			}
			
			Some( public_key )
		}
	}

	/// Generates a new private key for the given `key_type`.
	pub fn generate( key_type: KeyType ) -> Self {

		let inner = unsafe {
			match key_type {
				KeyType::Ecdsa => {
					let mut priv_key: GNUNET_CRYPTO_EcdsaPrivateKey = MaybeUninit::uninit().assume_init();
					GNUNET_CRYPTO_ecdsa_key_create( &mut priv_key as _ );

					GNUNET_IDENTITY_PrivateKey {
						type_: htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDSA ),
						__bindgen_anon_1: GNUNET_IDENTITY_PrivateKey__bindgen_ty_1 {
							ecdsa_key: priv_key
						}
					}
				},
				KeyType::Eddsa => {
					let mut priv_key: GNUNET_CRYPTO_EddsaPrivateKey = MaybeUninit::uninit().assume_init();
					GNUNET_CRYPTO_eddsa_key_create( &mut priv_key as _ );

					GNUNET_IDENTITY_PrivateKey {
						type_: htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_EDDSA ),
						__bindgen_anon_1: GNUNET_IDENTITY_PrivateKey__bindgen_ty_1 {
							eddsa_key: priv_key
						}
					}
				}
			}
		};

		Self ( inner )
	}

	pub fn sign( &self, data: &[u8], purpose: u32 ) -> Option<Signature> {
		assert!(data.len() < u32::max_value() as _, "unable to sign data larger than 2^64-1 bytes");

		// This struct represents the memory layout that GNUNET_IDENTITY_sign_ expects the data to be represented with.
		let mut buffer = Vec::with_capacity( mem::size_of::<GNUNET_CRYPTO_EccSignaturePurpose>() + data.len());
		buffer.extend_from_slice( &(data.len() as u32).to_be_bytes() );
		buffer.extend_from_slice( &purpose.to_be_bytes() );
		buffer.extend_from_slice( data );

		unsafe {

			let mut signature: GNUNET_IDENTITY_Signature = MaybeUninit::uninit().assume_init();
			let result = GNUNET_IDENTITY_sign_( &self.0 as _, &buffer as *const _ as _, &mut signature as _ );
			if result == GNUNET_GenericReturnValue_GNUNET_SYSERR {
				return None;
			}

			Some( Signature ( signature ) )
		}
	}
}

// Wipe the key from memory after use
impl Drop for PrivateKey {
	fn drop( &mut self ) {
		unsafe { self.0 = mem::zeroed() }
	}
}

impl PublicKey {

	/// Generates a base32 encoded string for the public key.
	fn _to_string( &self ) -> String {
		unsafe {
			let ptr = GNUNET_IDENTITY_public_key_to_string( &self.0 as _ );
			let cstr = CStr::from_ptr( ptr );
			let result = cstr.to_str().unwrap().to_owned();

			GNUNET_free( ptr as _ );
			result
		}
	}

	/// Parses a public key from its base32 representation.
	/// Returns None if it was not able to.
	pub fn from_string( string: &str ) -> Option<Self> {
		let cstring = CString::new( string ).expect("null character in string");

		unsafe {
			let mut inner: GNUNET_IDENTITY_PublicKey = MaybeUninit::uninit().assume_init();
			let result = GNUNET_IDENTITY_public_key_from_string( cstring.as_ptr(), &mut inner as _ );

			if result == GNUNET_GenericReturnValue_GNUNET_SYSERR {
				return None;
			}

			Some( Self ( inner ) )
		}
	}
}

impl Serialize for PublicKey {

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where
		S: Serializer
	{
		let mut seq = serializer.serialize_tuple( 33 )?;

		match self.0.type_ {
			KEYTYPE_ECDSA => seq.serialize_element( &0u8 )?,
			KEYTYPE_EDDSA => seq.serialize_element( &1u8 )?,
			other => return Err( S::Error::custom( &format!("invalid public key type found: {}", other) ) )
		};

		// The memory layout of ecdsa_signature and eddsa_signature in self.0.__bindgen_anon_1 is exactly the same,
		//  so we don't really care and just serialize one of them.
		unsafe {
			for byte in &self.0.__bindgen_anon_1.ecdsa_key.q_y {
				seq.serialize_element( byte as &u8 )?;
			}
		}

		seq.end()
	}
}

impl<'de> Deserialize<'de> for PublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where
		D: Deserializer<'de>
	{
		Ok( deserializer.deserialize_tuple( 33, PublicKeyVisitor )? )
	}
}

impl<'de> de::Visitor<'de> for PublicKeyVisitor {

	type Value = PublicKey;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a 65-byte octet string")
	}

	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where
		A: de::SeqAccess<'de>
	{
		let key_type: GNUNET_IDENTITY_KeyType = match seq.next_element()?.ok_or( de::Error::custom("missing key type") )? {
			0 => KEYTYPE_ECDSA,
			1 => KEYTYPE_EDDSA,
			other => return Err( de::Error::invalid_value(de::Unexpected::Unsigned(other as _), &"0 or 1") )
		};

		// Not initializing here is safe because the very next thing we do is initialize it with bytes
		let mut pubkey: GNUNET_IDENTITY_PublicKey__bindgen_ty_1 = unsafe { MaybeUninit::uninit().assume_init() };

		// The memory layout of the ecdsa signature and the eddsa signature is exactly the same.
		for i in 0..32 {
			unsafe { pubkey.ecdsa_key.q_y[i] = seq.next_element()?.unwrap() };
		}

		Ok( PublicKey (
			GNUNET_IDENTITY_PublicKey {
				type_: key_type,
				__bindgen_anon_1: pubkey
			}
		))
	}
}

impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self._to_string())
	}
}

impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self._to_string())
	}
}

impl Signature {

	pub fn verify( &self, purpose: u32, data: &[u8], public_key: &PublicKey ) -> bool {
		
		let mut buffer = Vec::with_capacity( mem::size_of::<GNUNET_CRYPTO_EccSignaturePurpose>() + data.len());
		buffer.extend_from_slice( &(data.len() as u32).to_be_bytes() );
		buffer.extend_from_slice( &purpose.to_be_bytes() );
		buffer.extend_from_slice( data );

		unsafe {
			let result = GNUNET_IDENTITY_signature_verify_( htonl(purpose), buffer.as_ptr() as _, &self.0 as _, &public_key.0 );

			result > 0
		}
	}
}

impl Serialize for Signature {

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where
		S: Serializer
	{
		let mut seq = serializer.serialize_tuple( 65 )?;

		match self.0.type_ {
			KEYTYPE_ECDSA => seq.serialize_element( &0u8 )?,
			KEYTYPE_EDDSA => seq.serialize_element( &1u8 )?,
			other => return Err( S::Error::custom( &format!("invalid signature type found: {}", other) ) )
		};

		// The memory layout of ecdsa_signature and eddsa_signature in self.0.__bindgen_anon_1 is exactly the same,
		//  so we don't really care and just serialize one of them.
		unsafe {
			for byte in &self.0.__bindgen_anon_1.ecdsa_signature.r {
				seq.serialize_element( byte )?;
			}
			
			for byte in &self.0.__bindgen_anon_1.ecdsa_signature.s {
				seq.serialize_element( byte )?;
			}
		}

		seq.end()
	}
}

impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where
		D: Deserializer<'de>
	{
		Ok( deserializer.deserialize_tuple( 65, SignatureVisitor )? )
	}
}

impl<'de> de::Visitor<'de> for SignatureVisitor {

	type Value = Signature;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a 65-byte octet string")
	}

	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where
    	A: de::SeqAccess<'de>
	{
		let key_type: GNUNET_IDENTITY_KeyType = match seq.next_element()?.ok_or( de::Error::custom("missing key type") )? {
			0 => KEYTYPE_ECDSA,
			1 => KEYTYPE_EDDSA,
			other => return Err( de::Error::invalid_value(de::Unexpected::Unsigned(other as _), &"0 or 1") )
		};

		// Not initializing here is safe because the very next thing we do is initialize it with bytes
		let mut sig: GNUNET_IDENTITY_Signature__bindgen_ty_1 = unsafe { MaybeUninit::uninit().assume_init() };

		// The memory layout of the ecdsa signature and the eddsa signature is exactly the same.
		for i in 0..32 {
			unsafe { sig.ecdsa_signature.r[i] = seq.next_element()?.unwrap() };
		}
		for i in 0..32 {
			unsafe { sig.ecdsa_signature.s[i] = seq.next_element()?.unwrap() };
		}

		Ok( Signature (
			GNUNET_IDENTITY_Signature {
				type_: key_type,
				__bindgen_anon_1: sig
			}
		))
	}
}