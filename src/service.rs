use async_std::{
	prelude::*,
	net::Shutdown,
	os::unix::net::UnixStream
};

use std::{
	io,
	mem::{MaybeUninit},
	ops::{Deref, DerefMut},
	path::*,
	sync::Arc
};

use crate::{
	common::*,
	error
};



pub struct Service {
	#[cfg(feature = "single_threaded")]
	unixpath: Rc<PathBuf>,
	#[cfg(not(feature = "single_threaded"))]
	unixpath: Arc<PathBuf>
}

pub struct Handle {
	pub(in crate) socket: UnixStream
}

pub struct MessageHeader {
	pub size: u16,
	pub type_: u16
}

/*pub struct Message<'a> {
	ptr: *mut u8,
	_phantom: PhantomData<&'a u8>
}

pub struct MessageHeader {
	size: u16,
	type_: u16
}

pub struct MessageWriter<'a> {
	ptr: *mut u8,
	_phantom: PhantomData<&'a u8>
}*/



#[macro_export]
macro_rules! decl_service {
	( $handle:ident ) => {
		pub struct $handle ( pub(in crate) crate::service::Handle );
	}
}

#[macro_export]
macro_rules! impl_service {
	( $handle:ty ) => {
		use std::ops::{Deref, DerefMut};

		impl Deref for $handle  {
			type Target = crate::service::Handle;

			fn deref( &self ) -> &crate::service::Handle {
				&self.0
			}
		}

		impl DerefMut for $handle  {
			fn deref_mut( &mut self ) -> &mut crate::service::Handle {
				&mut self.0
			}
		}

		impl From<crate::service::Handle> for $handle {
			fn from( handle: crate::service::Handle ) -> Self {
				Self ( handle )
			}
		}
	}
}



impl Service {

	pub async fn connect( &self ) -> io::Result<Handle> {
		let socket = UnixStream::connect( &*self.unixpath ).await?;

		Ok( Handle {
			socket
		})
	}

	pub fn new( unixpath: PathBuf ) -> Self {
		Self {
			unixpath: Arc::new( unixpath )
		}
	}
}

impl Handle {

	fn _disconnect( &self ) {
		match self.socket.shutdown( Shutdown::Both ) {
			Err(e) => eprintln!("Unable to shutdown socket: {}", e),
			Ok(()) => {}
		}
	}

	pub(in crate) unsafe fn clone( &self ) -> Self {
		Self {
			socket: self.socket.clone()
		}
	}

	/// Disconnects the unix domain socket related for the connection to the service.
	// Note: Invokes the drop implementation, which calls `self._disconnect`.
	pub fn disconnect( self ) {}

	pub(in crate) async fn read_as_bytes<T>( &mut self ) -> io::Result<T> {
		let mut data: T = unsafe { MaybeUninit::uninit().assume_init() };

		self.read( as_bytes_mut( &mut data ) ).await?;

		Ok( data )
	}

	pub(in crate) async fn read_bytes( &mut self, len: usize ) -> io::Result<Vec<u8>> {
		let mut buffer = vec![0u8; len];
		
		self.read( &mut buffer ).await?;

		Ok( buffer )
	}

	pub(in crate) async fn read_header( &mut self ) -> io::Result<MessageHeader> {

		let size = self.read_u16().await?;
		let type_ = self.read_u16().await?;
		
		Ok( MessageHeader {
			size,
			type_
		} )
	}

	// Reads the result.
	pub(in crate) async fn read_result( &mut self, message_size: u16 ) -> Result<(), error::Error> {
		
		let result_code = self.read_u32().await?;
		
		if result_code == 0 {
			return Ok(());
		}
		
		let msg = self.read_str_zt( message_size - 4 - 4 - 1 ).await?;

		let error = error::ResultError::new( result_code, msg );
		Err( error.into() )
	}

	pub(in crate) async fn read_str( &mut self, len: u16 ) -> io::Result<String> {
		let mut buf = vec![0u8; len as usize];
		
		self.read( &mut buf ).await?;
		
		Ok( String::from_utf8(buf).unwrap() )
	}

	pub(in crate) async fn read_str_zt( &mut self, len: u16 ) -> io::Result<String> {
		let mut buf = vec![0u8; len as usize];

		self.read( &mut buf ).await?;
		self.skip( 1 ).await?;	// Skip the termination character.

		Ok( String::from_utf8(buf).unwrap() )
	}

	pub(in crate) async fn read_u16( &mut self ) -> io::Result<u16> {
		let mut buf: [u8; 2] = unsafe { MaybeUninit::uninit().assume_init() };

		self.read( &mut buf ).await?;

		Ok( u16::from_be_bytes( buf ) )
	}

	pub(in crate) async fn read_u32( &mut self ) -> io::Result<u32> {
		let mut buf: [u8; 4] = unsafe { MaybeUninit::uninit().assume_init() };

		self.read( &mut buf ).await?;

		Ok( u32::from_be_bytes( buf ) )
	}

	pub(in crate) async fn skip( &mut self, len: usize ) -> io::Result<()> {
		let mut buf = vec![0u8; len];

		self.read( &mut buf ).await?;

		Ok(())
	}

	pub(in crate) async fn write_header( &mut self, type_: u16, size: u16 ) -> io::Result<()> {
		self.write_u16( size ).await?;
		self.write_u16( type_ ).await?;
		Ok(())
	}

	pub(in crate) async fn write_as_bytes<T>( &mut self, data: &T ) -> io::Result<usize> {
		self.write( as_bytes( data ) ).await
	}

	pub(in crate) async fn write_byte( &mut self, byte: u8 ) -> io::Result<()> {
		self.write( as_bytes( &byte ) ).await?; Ok(())
	}

	pub(in crate) async fn write_str( &mut self, data: &str ) -> io::Result<usize> {
		self.write( data.as_bytes() ).await
	}

	pub(in crate) async fn write_str_zt( &mut self, data: &str ) -> io::Result<()> {
		self.write( data.as_bytes() ).await?;
		self.write_byte( 0 ).await?;
		Ok(())
	}

	pub(in crate) async fn write_u16( &mut self, int: u16 ) -> io::Result<()> {
		self.write_as_bytes( &int ).await?; Ok(())
	}

	pub(in crate) async fn write_u32( &mut self, int: u32 ) -> io::Result<()> {
		self.write_as_bytes( &int ).await?; Ok(())
	}
}

impl Deref for Handle {
	type Target = UnixStream;

	fn deref( &self ) -> &Self::Target {
		&self.socket
	}
}

impl DerefMut for Handle {
	fn deref_mut( &mut self ) -> &mut Self::Target {
		&mut self.socket
	}
}

impl Drop for Handle {
	fn drop( &mut self ) {
		self._disconnect()
	}
}