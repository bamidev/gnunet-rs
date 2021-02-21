use crate::configuration;

use std::{
	env,
	ffi::CString,
	mem::MaybeUninit,
	ptr,
	os::raw::*
};

use gnunet_sys::*;


pub type GenericReturnValue = GNUNET_GenericReturnValue;



pub fn run<F>( binary_name: &str, helptext: &str, main: F ) -> GenericReturnValue where
	F: FnOnce(&configuration::Handle)
{
	let cbinary_name = CString::new(binary_name).expect("null character in binary name");
	let chelptext = CString::new(helptext).expect("null character in helptext");

	let closure = Box::into_raw( Box::new( main ) );

	let first_arg = CString::new( env::args().next().unwrap() ).unwrap();
	let empty = CString::new("").unwrap();
	let mut option: GNUNET_GETOPT_CommandLineOption = unsafe { MaybeUninit::uninit().assume_init() };
	option.shortName = 'a' as _;
	option.name = ptr::null(); //empty.as_ptr();
	option.argumentHelp = empty.as_ptr();
	option.description = empty.as_ptr();
	option.require_argument = GNUNET_GenericReturnValue_GNUNET_NO;
	option.option_mandatory = GNUNET_GenericReturnValue_GNUNET_NO;
	option.option_exclusive = GNUNET_GenericReturnValue_GNUNET_NO;
	option.processor = Some( ffi_command_processor );
	option.cleaner = Some( ffi_cleaner );

	let e = first_arg.as_ptr() as *mut c_char;

	// TODO: convert to C compatible argc and argv.
	unsafe { GNUNET_PROGRAM_run( 1, &e as _, cbinary_name.as_ptr(), chelptext.as_ptr(), &option, Some( ffi_main::<F> ), closure as _ ) }
}



extern "C" fn ffi_cleaner(_data: *mut c_void) {}

extern "C" fn ffi_command_processor( ctx: *mut GNUNET_GETOPT_CommandLineProcessorContext, scls: *mut c_void, option: *const c_char, value: *const c_char) -> c_int {
	eprintln!("ffi_command_processor"); 0
}

unsafe extern "C" fn ffi_main<F>(data: *mut c_void, args: *const *mut c_char, cfgfile: *const c_char, cfg: *const GNUNET_CONFIGURATION_Handle)
	where F: FnOnce(&configuration::Handle)
{
	let closure: Box<F> = Box::from_raw( data as _ );
	let configuration = configuration::Handle::from_inner( cfg as _ );
	closure( &configuration );
}