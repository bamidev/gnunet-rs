


pub struct Handle {
	inner: *mut GNUNET_MQ_Handle
}

pub struct MessageHandlerData {
	on_message_validation: Box<dyn FnMut()>
	on_message: Box<dyn FnMut()>
}

pub struct MessageHandler {
	inner: *mut GNUNET_MQ_MessageHandler
}



impl Handle {

	pub fn from_inner( inner: *mut GNUNET_MQ_Handle ) -> Self {
		Self {
			inner
		}
	}
}