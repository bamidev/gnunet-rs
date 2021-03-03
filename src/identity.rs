use gnunet_sys::*;
use async_std::prelude::*;
use serde::{*, ser::*};

use std::{
	collections::HashMap,
	ffi::*,
	fmt,
	io,
	mem::{self, MaybeUninit},
	os::raw::*,
	ptr
};

use crate::{
	common::*,
	configuration,
	crypto::HashCode,
	error,
	future::*,
	gnunet,
	service,
	decl_service, impl_service
};



decl_service!( Handle );
impl_service!( Handle );

pub struct Ego {
	pub name: String,
	pub private_key: PrivateKey
}

#[derive(Clone)]
pub struct PrivateKey ( GNUNET_IDENTITY_PrivateKey );

#[derive(Clone)]
pub struct PublicKey ( GNUNET_IDENTITY_PublicKey );

pub enum KeyType {
	Ecdsa = 0x00001000, // = htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDSA )
	Eddsa = 0x14001000  // = htonl( GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDDA )
}
const KEYTYPE_ECDSA: GNUNET_IDENTITY_KeyType = 0x00001000;
const KEYTYPE_EDDSA: GNUNET_IDENTITY_KeyType = 0x14001000;

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

	pub async fn connect( gnunet: gnunet::Handle ) -> io::Result<Self> {

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

			let (name, private_key, end_of_line) = self.read_update( header.size - 4 ).await?;
			egos.insert( name, private_key );
		}

		Ok(egos)
	}

	/// Looks up an ego by name.
	/// If found, returns its private key.
	pub async fn lookup( &mut self, name: &str ) -> io::Result<error::Result<Option<PrivateKey>>> {
		
		self.0.write_header( GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP as _, (4 + name.len() + 1) as _ ).await?;
		self.0.write_str_zt( name ).await?;
		self.0.flush().await?;
		
		let header = self.0.read_header().await?;
		if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _ {
			let result = self.0.read_result( header.size ).await?;
			
			match result {
				Ok(()) => Err( io::Error::from( io::ErrorKind::InvalidData ) ),
				Err(e) => {
					if e.code == 99999 {
						Ok( Ok( None ) )
					} else {
						Ok( Err(e) )
					}
				}
			}
		}
		else if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE as _ {
			
			let (_, private_key, _) = self.read_update( header.size - 4 ).await?;
			Ok( Ok( Some( private_key ) ) )
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
	pub async fn create( &mut self, name: &str, private_key: PrivateKey ) -> io::Result<Result<bool, error::Error>> {

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
		
		let result = self.0.read_result( header.size ).await?;

		// Transform gnunet error 1 into false, because it indicates the ego already existed.
		match result {
			Ok(()) => Ok(Ok(true)),
			Err(e) => {
				if e.code == 1 {
					Ok(Ok(false))
				} else {
					Ok(Err(e))
				}
			}
		}
	}

	/// Gets the default ego for the given service.
	pub async fn get_default( &mut self, service: &str ) -> io::Result<error::Result<Option<Ego>>> {

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
			return Ok(Ok(Some(Ego::new(name, private_key))));
		}

		if header.type_ == GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE as _ {
			let result = self.0.read_result( header.size ).await?;
			return Ok(Err(result.expect_err("succesful result received")));
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
	pub async fn set_default( &mut self, service: &str, ego: &Ego ) -> io::Result<error::Result<()>> {

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

	pub fn sign( &self, data: &[u8; 32], purpose: u32 ) -> Option<Signature> {
		assert!(data.len() < u32::max_value() as _, "unable to sign data larger than 2^32-1 bytes");

		// This struct represents the memory layout that GNUNET_IDENTITY_sign_ expects the data to be represented with.
		#[repr(C)]
		struct Data {
			purpose: GNUNET_CRYPTO_EccSignaturePurpose,
			data: [u8; 32]
		}

		unsafe {
			let raw_data = Data {
				purpose: GNUNET_CRYPTO_EccSignaturePurpose {
					size: htonl( data.len() as _ ),
					purpose: htonl( purpose )
				},
				data: data.clone()
			};

			let mut signature: GNUNET_IDENTITY_Signature = MaybeUninit::uninit().assume_init();
			let result = GNUNET_IDENTITY_sign_( &self.0 as _, &raw_data as *const _ as _, &mut signature as _ );
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
	pub fn to_string( &self ) -> String {
		unsafe {
			let ptr = GNUNET_IDENTITY_public_key_to_string( &self.0 as _ );
			let cstr = CStr::from_ptr( ptr );
			let result = cstr.to_str().unwrap().to_owned();

			GNUNET_free( ptr as _ );
			result
		}
	}
}

impl Signature {
}

impl Serialize for Signature {

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where
		S: Serializer
	{
		let mut seq = serializer.serialize_seq( Some(2) )?;

		match self.0.type_ {
			KEYTYPE_ECDSA => seq.serialize_element( &0u8 )?,
			KEYTYPE_EDDSA => seq.serialize_element( &1u8 )?,
			_ => panic!("invalid signature type found")
		};

		// The memory layout of ecdsa_signature and eddsa_signature in self.0.__bindgen_anon_1 is exactly the same,
		//  so we don't really care and just serialize one of them.
		unsafe {
			seq.serialize_element( as_bytes( &self.0.__bindgen_anon_1.ecdsa_signature.r ) )?;
			seq.serialize_element( as_bytes( &self.0.__bindgen_anon_1.ecdsa_signature.s ) )?;
		}

		seq.end()
	}
}

impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where
		D: Deserializer<'de>
	{
		Ok( deserializer.deserialize_seq( SignatureVisitor )? )
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
 		sig.ecdsa_signature.r = seq.next_element()?.ok_or( de::Error::custom("missing signature r") )?;
		sig.ecdsa_signature.s = seq.next_element()?.ok_or( de::Error::custom("missing signature s") )?;

		Ok( Signature (
			GNUNET_IDENTITY_Signature {
				type_: key_type,
				__bindgen_anon_1: sig
			}
		))
	}
}