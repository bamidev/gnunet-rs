use gnunet_sys::*;

use std::{
	ptr,
	os::raw::*
};



pub struct Task ( *mut GNUNET_SCHEDULER_Task );



pub fn add_now<T>( task: T ) -> Task where
	T: FnOnce()
{
	let cls = Box::into_raw( Box::new( task ) );

	let inner = unsafe { GNUNET_SCHEDULER_add_now( Some( ffi_task_callback::<T> ), cls as _ ) };
	assert!(inner != ptr::null_mut(), "GNUNET_SCHEDULER_add_now returned NULL pointer");
	Task ( inner )
}

pub fn add_shutdown<T>( task: T ) -> Task where
	T: FnOnce()
{
	let cls = Box::into_raw( Box::new( task ) );

	let inner = unsafe { GNUNET_SCHEDULER_add_shutdown( Some( ffi_task_callback::<T> ), cls as _ ) };
	assert!(inner != ptr::null_mut(), "GNUNET_SCHEDULER_add_shutdown returned NULL pointer");
	Task ( inner )
}

pub fn wait_on_task<T,R>( task: T ) where
	T: FnOnce() -> R
{
	let cls = Box::into_raw( Box::new( task ) );


}



unsafe extern "C" fn ffi_task_callback<T>( cls: *mut c_void ) where
	T: FnOnce()
{
	let task: Box<T> = Box::from_raw( cls as _ );
	let result = task();
}