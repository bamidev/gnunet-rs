use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::raw::*;



#[derive(Debug)]
pub enum Error {
	/// Indicates an unsuccesful result received from the Gnunet service.
	Result( ResultError ),
	Io( io::Error )
}

#[derive(Debug)]
pub struct ResultError {
	pub code: u32,
	msg: String
}

#[derive(Debug)]
pub struct MsgError {
	msg: String
}

pub type Result<T> = std::result::Result<T, Error>;



impl MsgError {

	pub fn new( msg: *const c_char ) -> Self {
		Self {
			msg: unsafe { CStr::from_ptr( msg ) }.to_str().unwrap().to_owned()
		}
	}
}

impl ResultError {

	pub fn new( code: u32, msg: String ) -> Self {
		Self {
			code,
			msg
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Result( e ) => write!(f, "unsuccessful result: {}", e),
			Self::Io( e ) => write!(f, "I/O error: {}", e)
		}
	}
}

impl From<io::Error> for Error {
	fn from( e: io::Error ) -> Self {
		Self::Io(e)
	}
}

impl From<ResultError> for Error {
	fn from( e: ResultError ) -> Self {
		Self::Result(e)
	}
}

impl fmt::Display for ResultError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", &self.msg )
	}
}

impl fmt::Display for MsgError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", &self.msg )
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl std::error::Error for ResultError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl std::error::Error for MsgError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}