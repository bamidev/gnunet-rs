use std::{
	future::Future,
	mem,
	pin::Pin,
	task::{Context, Poll}
};



/// This is a future which allows you to turn functions that provide results or signify completion through callbacks, into a future.
/// A closure is provided to [`CallbackFuture::new`], which in turn provides a callable object to wake the future with and to give the result to.
pub struct CallbackFuture<C, R> where
	C: FnOnce( Box<dyn FnOnce(R)> ),
	R: 'static
{
	started: bool,
	closure: Option<Box<C>>,
	result: Option<R>
}

impl<C, R> Unpin for CallbackFuture<C, R> where
	C: FnOnce( Box<dyn FnOnce(R)> ),
	R: 'static
{}



impl<C, R> CallbackFuture<C, R> where
	C: FnOnce( Box<dyn FnOnce(R)> ),
	R: 'static
{
	pub fn new( closure: C ) -> Self {
		Self {
			started: false,
			closure: Some(Box::new(closure)),
			result: None
		}
	}
}

impl<C, R> Future for CallbackFuture<C, R> where
	C: FnOnce( Box<dyn FnOnce(R)> ),
	R: 'static
{
	type Output = R;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {

		if !self.started {
			self.started = true;

			// Prepare a closure that can be used to set a result and wake the future.
			// This closure will be passed to `self.closure`.
			let waker = cx.waker().clone();
			let result_ptr = &mut self.result as *mut Option<R>;
			let waker_fn = Box::new( move |result| {

				// This is considered safe because it is called before the waker is waked.
				// We can assume that the future struct is still in memory before the waker is used.
				unsafe { *result_ptr = Some( result ) };
				eprintln!("SET RESULT");
				waker.wake();
			} );

			// Move ownership so that we can invoke the closure
			let mut closure: Option<Box<C>> = None;
			mem::swap( &mut self.closure, &mut closure );

			// Invoke the closure
			(closure.unwrap())( waker_fn );
			Poll::Pending
		}
		else {

			if !self.result.is_none() {	eprintln!("POLL TEST");
				// Move ownership so that we can return the result
				let mut result: Option<R> = None;
				mem::swap( &mut self.result, &mut result );
				eprintln!("FUTUREU RESULT");
				Poll::Ready( result.unwrap() )
			}
			else {	eprintln!("POLL TEST2");
				Poll::Pending
			}
		}
	}
}