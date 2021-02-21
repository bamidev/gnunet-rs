use gnunet_sys::*;

use std::os::raw::*;
use std::slice;



pub struct Handle ( *mut GNUNET_MQ_Handle );

pub struct MessageHandle ( *const GNUNET_MessageHeader );

pub struct MessageHandlerData {
	on_message_validation: Box<dyn FnMut()>,
	on_message: Box<dyn FnMut()>
}

pub struct MessageHandler ( pub(in crate) GNUNET_MQ_MessageHandler );



impl Handle {

	pub fn from_inner( inner: *mut GNUNET_MQ_Handle ) -> Self {
		Self ( inner )
	}
}

impl MessageHandle {

	pub fn size( &self ) -> u16 { unsafe { (*self.0).size } }

	pub fn type_( &self ) -> u16 { unsafe { (*self.0).type_ } }

	pub fn content( &self ) -> &[u8] {
		unsafe {
			let data_ptr = self.0.offset(1);
			slice::from_raw_parts( data_ptr as *const u8, self.size() as usize )
		}
	}
}

impl MessageHandler {

	pub fn new_static_sized<M>( type_: u16, on_message: M, expected_size: u16 ) -> Self where
		M: FnMut(MessageHandle)
	{
		let cls = Box::into_raw( Box::new(
			on_message
		));

		Self ( GNUNET_MQ_MessageHandler {
			mv: None,
			cb: Some( ffi_message_handler::<M> ),
			cls: cls as _,
			type_,
			expected_size
		} )
	}
}



unsafe extern "C" fn ffi_message_handler<M>( cls: *mut c_void, msg: *const GNUNET_MessageHeader ) where
	M: FnMut(MessageHandle)
{
	let mut on_message: Box<M> = Box::from_raw( cls as _ );
	let message = MessageHandle ( msg );

	on_message( message );
}