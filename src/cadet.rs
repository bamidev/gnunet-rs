use gnunet_sys::*;

use std::{
	ptr,
	os::raw::*
};

use crate::configuration;
use crate::crypto::*;
use crate::mq;



pub struct Handle ( pub(in crate) *mut GNUNET_CADET_Handle );

pub struct Channel ( *mut GNUNET_CADET_Channel );

struct ChannelClosureData<W,D> where
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{
	on_window_change: W,
	on_disconnect: D
}

pub struct Port ( *mut GNUNET_CADET_Port );

struct PortClosureData<C,W,D> where
	C: FnMut(&mut Channel, &PeerIdentity),
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{
	on_connect: C,
	c: ChannelClosureData<W,D>
}

unsafe impl Send for Handle {}



impl Handle {

	pub fn connect( config: &configuration::Handle ) -> Self {

		let inner = unsafe { GNUNET_CADET_connect( config.0 ) };
		assert!(inner != ptr::null_mut(), "null handler");
		Self ( inner )
	}

	pub fn create_channel<W,D>( &mut self, destination: &PeerIdentity, port: &HashCode, on_window_change: W, on_disconnect: D, handlers: &mq::MessageHandler ) -> Channel where
		W: FnMut(&Channel, usize),
		D: FnMut(&Channel)
	{
		let cls = Box::into_raw( Box::new(
			ChannelClosureData {
				on_window_change: Box::new( on_window_change ),
				on_disconnect: Box::new( on_disconnect )
			}
		) );

		let inner = unsafe { GNUNET_CADET_channel_create( self.0,
			cls as _,
			&destination.0 as _,
			&port.0 as _, 
			Some( ffi_window_change::<W,D> ),
			Some( ffi_disconnect::<W,D> ),
			&handlers.0 as _
		) };

		Channel ( inner )
	}

	pub fn disconnect( self ) {
		unsafe { GNUNET_CADET_disconnect( self.0 ) };
	}

	pub fn open_port<C,W,D>( &mut self, port: &HashCode, on_connect: C, on_window_change: W, on_disconnect: D, handlers: &mq::MessageHandler ) -> Port where
		C: FnMut(&mut Channel, &PeerIdentity),
		W: FnMut(&Channel, usize),
		D: FnMut(&Channel)
	{

		let cls = Box::into_raw( Box::new(
			PortClosureData {
				on_connect,
				c: ChannelClosureData {
					on_window_change,
					on_disconnect
				}
			}
		) );

		let inner = unsafe { GNUNET_CADET_open_port( self.0,
			&port.0 as _,
			Some( ffi_connect_handler::<C,W,D> ),
			cls as _,
			Some( ffi_port_window_change_handler::<C,W,D> ),
			Some( ffi_port_disconnect_handler::<C,W,D> ),
			&handlers.0 as _
		) };

		Port ( inner )
	}
}

impl Port {
	pub fn close( self ) {
		unsafe { GNUNET_CADET_close_port( self.0 ) };
	}
}



unsafe extern "C" fn ffi_connect_handler<C,W,D>( cls: *mut c_void, _channel: *mut GNUNET_CADET_Channel, _source: *const GNUNET_PeerIdentity ) -> *mut c_void where
	C: FnMut(&mut Channel, &PeerIdentity),
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{
	let mut data: Box<PortClosureData<C,W,D>> = Box::from_raw( cls as _ );
	let mut channel = Channel ( _channel as _ );
	let source = PeerIdentity ( *_source );

	(data.on_connect)( &mut channel, &source );

	cls
}

unsafe extern "C" fn ffi_window_change<W,D>( cls: *mut c_void, _channel: *const GNUNET_CADET_Channel, window_size: c_int ) where
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{
	let mut data: Box<ChannelClosureData<W,D>> = Box::from_raw( cls as _ );
	let channel = Channel ( _channel as _ );

	(data.on_window_change)( &channel, window_size as _ );
}

unsafe extern "C" fn ffi_disconnect<W,D>( cls: *mut c_void, _channel: *const GNUNET_CADET_Channel ) where
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{

	let mut data: Box<ChannelClosureData<W,D>> = Box::from_raw( cls as _ );
	let channel = Channel ( _channel as _ );

	(data.on_disconnect)( &channel );
}

unsafe extern "C" fn ffi_port_window_change_handler<C,W,D>( cls: *mut c_void, _channel: *const GNUNET_CADET_Channel, window_size: c_int ) where
	C: FnMut(&mut Channel, &PeerIdentity),
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{
	let mut data: Box<PortClosureData<C,W,D>> = Box::from_raw( cls as _ );
	let channel = Channel ( _channel as _ );

	(data.c.on_window_change)( &channel, window_size as _ );
}

unsafe extern "C" fn ffi_port_disconnect_handler<C,W,D>( cls: *mut c_void, _channel: *const GNUNET_CADET_Channel ) where
	C: FnMut(&mut Channel, &PeerIdentity),
	W: FnMut(&Channel, usize),
	D: FnMut(&Channel)
{

	let mut data: Box<PortClosureData<C,W,D>> = Box::from_raw( cls as _ );
	let channel = Channel ( _channel as _ );

	(data.c.on_disconnect)( &channel );
}