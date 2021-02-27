use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::os::raw::*;



#[derive(Debug)]
pub struct MsgError {
	msg: String
}



impl MsgError {

	pub fn new( msg: *const c_char ) -> Self {
		let x = Self {
			msg: unsafe { CStr::from_ptr( msg ) }.to_str().unwrap().to_owned()
		};

		eprintln!("TEST: {}",&x.msg);

		x
	}
}

impl fmt::Display for MsgError {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

		write!(f, "{}", &self.msg )
	}
}

impl Error for MsgError {
	fn source(&self) -> Option<&(dyn Error + 'static)> { None }
}