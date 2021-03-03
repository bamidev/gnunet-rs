use std::ffi::CStr;
use std::fmt;
use std::os::raw::*;



#[derive(Debug)]
pub struct Error {
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

impl Error {

	pub fn new( code: u32, msg: String ) -> Self {
		Self {
			code,
			msg
		}
	}
}

impl fmt::Display for Error {
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

impl std::error::Error for MsgError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}