use gnunet_sys::*;

use std::{
	ffi::*,
	mem::MaybeUninit,
	os::raw::*,
	ptr
};

use crate::{
	configuration,
	crypto::HashCode,
	error::*,
	future::*
};



pub struct Ego ( *mut GNUNET_IDENTITY_Ego );
pub struct Handle ( *mut GNUNET_IDENTITY_Handle );
pub type IdentityCallback = dyn FnMut(Ego, &str, &'static mut *mut ());
pub struct Operation ( *mut GNUNET_IDENTITY_Operation );
pub struct PrivateKeyHandle ( *mut GNUNET_IDENTITY_PrivateKey );
pub struct PublicKey ( GNUNET_IDENTITY_PublicKey );
pub enum KeyType {
	Ecdsa,
	Eddsa
}


unsafe impl Send for Ego {}
unsafe impl Send for Handle {}
unsafe impl Send for Operation {}
unsafe impl Send for PrivateKeyHandle {}


impl Ego {

	/// Obtains the ego that represents 'anonymous' users.
	pub fn anonymous() -> Self {
		let inner = unsafe { GNUNET_IDENTITY_ego_get_anonymous() };
		Self ( inner )
	}

	pub fn get_public_key( &self ) -> PublicKey {
		unsafe {
			let mut public_key: PublicKey = MaybeUninit::uninit().assume_init();

			GNUNET_IDENTITY_ego_get_public_key( self.0, &mut public_key.0 as _ );

			public_key
		}
	}

	pub fn lookup<C>( config: &configuration::Handle, name: &str, callback: C ) where
		C: FnOnce( Option<Ego> )
	{
		let cname = CString::new(name).expect("null character in `name`");
		let cls = Box::into_raw( Box::new( callback ) );

		unsafe { GNUNET_IDENTITY_ego_lookup( config.0, cname.as_ptr(), Some( ffi_lookup_callback::<C> ), cls as _ ) };
	}

	pub async fn lookup_async( config: &configuration::Handle, name: &str ) -> Option<Ego> {
		CallbackFuture::new(|wake| {
			Self::lookup( config, name, |result| {
				wake( result );
			})
		}).await
	}
}

impl Handle {

	/// Connects to the identity service, and gives all available ego's through `on_ego`.
	/// 
	/// *Warning*: Currently there is a bug which makes other functions assert if you connected to the identity service with this.
	///            For the time being, use `connect_and_list( &config, |_,_,_|{})` instead.
	pub fn connect( config: &configuration::Handle ) -> Self {
		
		let inner = unsafe { GNUNET_IDENTITY_connect( config.0, None, ptr::null_mut() ) };
		assert!(inner != ptr::null_mut(), "unable to connect to identity service");
		Self ( inner )
	}

	/// Connects to the identity service, and gives all available ego's through `on_ego`.
	pub fn connect_and_list<C>( config: &configuration::Handle, on_ego: C ) -> Self where
		C: FnMut(Ego, &str, &'static mut *mut ())
	{
		let cls = Box::into_raw( Box::new( on_ego ) );
		
		let inner = unsafe { GNUNET_IDENTITY_connect( config.0, Some( ffi_identity_callback::<C> ), cls as _ ) };
		assert!(inner != ptr::null_mut(), "unable to connect to identity service");
		Self ( inner )
	}

	/// Create a new ego with the given name.
	/// 
	/// # Arguments
	/// * `name` - desired name
	/// * `private_key` - desired private key, or `None` to create one
	/// * `key_type` - the type of key to create. Ignored if `private_key` is `None`.
	/// * `on_complete` - The closure that will be called with the result
	/// 
	/// # Returns
	/// A handle to abort the operation
	pub fn create<C>( &mut self, name: &str, private_key: Option<PrivateKeyHandle>, key_type: KeyType, on_complete: C ) -> Operation where
		C: FnOnce(Result<PrivateKeyHandle, MsgError>)
	{
		let cname = CString::new(name).expect("null character in name");
		let cprivate_key = match private_key {
			Some(key) => key.0,
			None => ptr::null(),
		};
		let ckey_type = match key_type {
			KeyType::Ecdsa => GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_ECDSA,
			KeyType::Eddsa => GNUNET_IDENTITY_KeyType_GNUNET_IDENTITY_TYPE_EDDSA
		};
		let cls = Box::into_raw( Box::new( on_complete ) );
		eprintln!("GNUNET_IDENTITY_create");
		let inner = unsafe { GNUNET_IDENTITY_create( self.0, cname.as_ptr(), cprivate_key, ckey_type, Some( ffi_create_callback::<C> ), cls as _ ) };
		Operation( inner )
	}

	/// Create a new ego with the given name.
	/// 
	/// # Arguments
	/// * `name` - desired name
	/// * `private_key` - desired private key, or `None` to create one
	/// * `key_type` - the type of key to create. Ignored if `private_key` is `None`.
	/// * `on_complete` - The closure that will be called with the result
	/// 
	/// # Returns
	/// The new private key (handle), or an error
	pub async fn create_async( &mut self, name: &str, private_key: Option<PrivateKeyHandle>, key_type: KeyType ) -> Result<PrivateKeyHandle, MsgError> {

		CallbackFuture::new(|wake| { eprintln!("callback_future");
			self.create( name, private_key, key_type, |result| {eprintln!("callback_future2");
				wake( result );
			});
		}).await
	}

	/// Obtains a default ego associated with the given service.
	pub fn default_ego( &mut self, service: &str, callback: impl FnMut(Ego, &str, &'static mut *mut ()) ) -> Operation {
		self.get( service, callback )
	}

	/// Disconnects from the identity service.
	pub fn disconnect( self ) {
		unsafe { GNUNET_IDENTITY_disconnect( self.0 ) };
	}

	/// Same as `default_ego`.
	pub fn get<C>( &mut self, service: &str, callback: C ) -> Operation where
		C: FnMut(Ego, &str, &'static mut *mut ())
	{
		let cservice = CString::new(service).expect("null character in `service`");
		let cls = Box::into_raw( Box::new( callback ) );
 
		let inner = unsafe { GNUNET_IDENTITY_get( self.0, cservice.as_ptr(), Some( ffi_identity_callback::<C> ), cls as _ ) };
		Operation ( inner )
	}
}

impl Drop for Handle {
	fn drop( &mut self ) {
		
	}
}

impl Operation {

	pub fn cancel( self ) {
		unsafe { GNUNET_IDENTITY_cancel( self.0 ) };
	}
}

impl PublicKey {

	pub fn to_string( &self ) -> String {
		unsafe {
			let ptr = GNUNET_IDENTITY_public_key_to_string( &self.0 as _ );
			let cstr = CStr::from_ptr( ptr );
			let result = cstr.to_str().unwrap();

			GNUNET_free( ptr as _ );
			result.to_owned()
		}
	}
}



unsafe extern "C" fn ffi_create_callback<C>( cls: *mut c_void, pk: *const GNUNET_IDENTITY_PrivateKey, emsg: *const c_char ) where
	C: FnOnce(Result<PrivateKeyHandle, MsgError>)
{
	if cls == ptr::null_mut() {
		return
	}

	let closure: Box<C> = Box::from_raw( cls as _ );

	if emsg == ptr::null() {
		let private_key = PrivateKeyHandle ( pk as _ );
		closure( Ok( private_key ) );
	}
	else {
		let error = MsgError::new( emsg );
		closure( Err( error ) );
	}
}

unsafe extern "C" fn ffi_identity_callback<C>(
	cls: *mut c_void,
	_ego: *mut GNUNET_IDENTITY_Ego,
	_ctx: *mut *mut c_void,
	name: *const c_char
) where C: FnMut(Ego, &str, &'static mut *mut ()) {

	if _ego != ptr::null_mut() {
		let mut closure: Box<C> = Box::from_raw( cls as _ );
		let ego = Ego ( _ego );
		let ctx = &mut *(_ctx as *mut *mut ());
		let cname = CStr::from_ptr( name ).to_str().expect("invalid name");

		closure( ego, cname, ctx );
	}
}

unsafe extern "C" fn ffi_lookup_callback<C>( cls: *mut c_void, _ego: *mut GNUNET_IDENTITY_Ego ) where
	C: FnOnce( Option<Ego> )
{
	let closure: Box<C> = Box::from_raw( cls as _ );
	let ego = if _ego == ptr::null_mut() {
		Some( Ego( _ego ) )
	} else { None };

	closure( ego );
}