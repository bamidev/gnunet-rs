use gnunet_sys::*;

use crate::configuration;



pub struct Handle ( *mut GNUNET_CADET_Handle );

pub struct Channel ( *mut GNUNET_CADET_Channel );

struct ChannelClosureData {
	on_window_change: Box<dyn FnMut(&Channel, usize)>
	on_disconnect: Box<dyn FnOnce(&Channel)>
}



impl Handle {

	pub fn connect( config: &configuration::Handle ) -> Self {

		let inner = unsafe { GNUNET_CADET_connect( config.inner ) };

		Self {
			inner
		}
	}

	pub fn create_channel( &mut self, destination: &PeerIdentity, port: &HashCode, on_window_change: impl FnMut(&Channel, usize), on_disconnect: impl FnOnce(&Channel), handlers: &MessageHandler ) -> Self {
		let cls = Box::into_raw( Box::new(
			ChannelClosureData {
				on_window_change,
				on_disconnect
			}
		) );

		let inner = unsafe { GNUNET_CADET_channel_create( self.0,
			cls as _,
			&destination.0 as _,
			&port.0 as _, 
			Some( ffi_window_change ),
			Some( ffi_disconnect ),
			handlers as _
		 ) };

		 Self ( inner )
	}

	pub fn disconnect( self ) {
		unsafe { GNUNET_CADET_disconnect( config.inner ) };
	}
}