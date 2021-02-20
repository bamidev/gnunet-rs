use gnunet_sys::*;



pub struct Handle {
	inner: *mut GNUNET_CORE_Handler
}



impl Handle {

	pub fn connect<S,C,D>( on_done: S, on_connect: C, on_disconnect: D ) -> Self where
		S: FnOnce( PeerIdentity ),
		C: FnMut( PeerIdentity, mq::Handle ),
		D: FnMut( PeerIdentity )
	{
		let inner = unsafe{ GNUNET_CORE_connect( ptr::null(), ptr::null_mut(), Some(ffi_done_handler), Some(ffi_connect_handler), Some(ffi_disconnect_handler) ) };

		Self {
			inner
		}
	}

	pub fn disconnect( &mut self ) {
		unsafe { GNUNET_CORE_disconnect( self.inner ) };
	}
}



unsafe extern "C" fn ffi_connect_handler<C>( data: *mut c_void, _my_id: *const GNUNET_PeerIdentity, queue: *const GNUNET_MQ_Handle ) where
	C: FnOnce(PeerIdentity, mq::Handle)
{

	let on_connect: Box<C> = Box::from_raw( data as _ );
	let my_id = PeerIdentity::from_inner( _myid );
	let mq = mq::Handle::from_inner( queue );
	on_done( my_id, mq )
}

unsafe extern "C" fn ffi_disconnect_handler<D>( data: *mut c_void, _my_id: *const GNUNET_PeerIdentity ) 
	D: FnOnce(PeerIdentity)
{

	let on_disconnect: Box<D> = Box::from_raw( data as _ );
	let my_id = PeerIdentity::from_inner( _my_id );
	on_done( my_id )
}

unsafe extern "C" fn ffi_done_handler<S>( data: *mut c_void, _my_id: *const GNUNET_PeerIdentity )
	S: FnOnce(PeerIdentity)
{

	let on_done: Box<S> = Box::from_raw( data as _ );
	let my_id = PeerIdentity::from_inner( _my_id );
	on_done( my_id )
}