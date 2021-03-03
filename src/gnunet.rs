use crate::{configuration, service};



/// The main handle to start service connections from.
#[derive(Clone, Default)]
pub struct Handle {
	pub(in crate) config: configuration::Handle
}



impl Handle {
	pub fn new( config: configuration::Handle ) -> Self {
		Self {
			config
		}
	}

	pub fn service( &self, service: &str ) -> service::Service {
		let unixpath = self.config.get_value_filename( service, "UNIXPATH" );
		service::Service::new( unixpath )
	}
}