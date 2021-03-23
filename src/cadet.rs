use gnunet_sys::*;

use std::{
	collections::HashMap,
	fmt,
	future::Future,
	io,
	mem,
	ops::Deref,
	pin::Pin,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering}
	}
};

use async_std::{
	channel::{self, Receiver, Sender},
	prelude::*,
	sync::Mutex
};

use crate::{
	crypto::*,
	error,
	identity::PublicKey,
	gnunet,
	service
};



pub struct Channel {
	handle: Handle,
	id: u32,
	receiver: ChannelReceiver
}

#[derive(Clone)]
pub struct ChannelReceiver ( Receiver<ChannelMessage> );

#[derive(Clone)]
pub struct Handle {
	inner: Arc<Mutex<service::Handle>>,
	shared: Arc<SharedData>
}

pub const PRIORITY_PREFERENCES_BACKGROUND: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PRIO_BACKGROUND;
pub const PRIORITY_PREFERENCES_BEST_EFFORT: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PRIO_BEST_EFFORT;
pub const PRIORITY_PREFERENCES_URGENT: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PRIO_URGENT;
pub const PRIORITY_PREFERENCES_CIRITICAL_CONTROL: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PRIO_CRITICAL_CONTROL;
pub const PRIORITY_PREFERENCES_MASK: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PRIORITY_MASK;
pub const PRIORITY_PREFERENCES_UNRELIABLE: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PREF_UNRELIABLE;
pub const PRIORITY_PREFERENCES_LOW_LATENCY: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PREF_LOW_LATENCY;
pub const PRIORITY_PREFERENCES_CORK_ALLOWED: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PREF_CORK_ALLOWED;
pub const PRIORITY_PREFERENCES_GOODPUT: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PREF_GOODPUT;
pub const PRIORITY_PREFERENCES_OUT_OF_ORDER: u32 = GNUNET_MQ_PriorityPreferences_GNUNET_MQ_PREF_OUT_OF_ORDER;

struct SharedData {
	run_flag: AtomicBool,
	channels: Mutex<HashMap<u32, Sender<ChannelMessage>>>
}

enum ChannelMessage {
	/// Message that a channel may begin to send data
	Ack,
	/// Message containing payload data
	Payload( ChannelMessagePayload ),
	/// Message signifying the destruction of the channel, whether our side initiated it or the other side.
	Destroy
}

pub struct ChannelMessagePayload {
	pub priority_flags: u32,
	pub payload: Vec<u8>
}

#[derive(Debug)]
struct PrematureDestroyError {}



impl Channel {

	/// Sends a termination message to the other side.
	pub async fn destroy( &mut self ) -> io::Result<()> {

		let mut h = self.handle.inner.lock().await;
		h.write_header( GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY as _, (4 + 4) as _ ).await?;
		h.write_u32( self.id ).await?;

		Ok(())
	}

	pub fn clone_receiver( &self ) -> ChannelReceiver {
		self.receiver.clone()
	}

	/// An internal ID.
	/// Can be used to differentiate between two channels.
	pub fn id( &self ) -> u32 {
		self.id
	}

	pub fn receiver( &self ) -> &ChannelReceiver {
		&self.receiver
	}

	/// Sends a message 
	pub async fn send( &mut self, priority: u32, data: &[u8] ) -> io::Result<()> {
		let mut h = self.handle.inner.lock().await;

		let len = 4 + 4 + 4 + data.len();
		h.write_header( GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA as _, len as _ ).await?;
		h.write_u32( self.id ).await?;
		h.write_u32( priority ).await?;
		h.write( data ).await?;

		// TODO: Wait for ack

		Ok(())
	}
}

impl Deref for Channel {
	type Target =  ChannelReceiver;

	fn deref( &self ) -> &Self::Target {
		self.receiver()
	}
}

impl ChannelReceiver {

	/// Receives a byte buffer from this channel, or None to indicate channel destruction.
	/// If this is called after having received None once, this will hang indefinitally.
	pub async fn receive( &self ) -> Option<ChannelMessagePayload> {
		let x = self.0.recv().await.unwrap();

		match x {
			ChannelMessage::Ack => panic!("unexpected ack message received"),
			ChannelMessage::Destroy => None,
			ChannelMessage::Payload( payload ) => Some( payload )
		}
	}
}

impl Handle {

	pub async fn channel_connect( &self, destination: &PublicKey, port: &HashCode ) -> io::Result<Channel> {

		let (channel_id, rx) = self.next_free_channel().await;
		let mut h = self.inner.lock().await;

		// Write request
		let header_size = 4 + 4 + mem::size_of::<GNUNET_PeerIdentity>() + mem::size_of::<GNUNET_HashCode>() + 4;
		h.write_header( GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE as _, header_size as _ ).await?;
		h.write_u32( channel_id ).await?;
		h.write_as_bytes( &destination.0 ).await?;
		h.write_as_bytes( &port.0 ).await?;
		h.write_u32( 0 ).await?;

		// Wait until we received the ack message
		let msg = rx.recv().await.unwrap();
		loop {
			match msg {
				ChannelMessage::Ack => return Ok( Channel {
					handle: self.clone(),
					id: channel_id,
					receiver: ChannelReceiver( rx )
				}),
				ChannelMessage::Destroy => return Err( io::Error::new( io::ErrorKind::ConnectionReset, PrematureDestroyError{} ) ),
				ChannelMessage::Payload(_) => eprintln!("Premature message received from cadet for channel {}", &channel_id)
			}
		}
	}

	pub async fn connect( gnunet: gnunet::Handle ) -> io::Result<Self> {
		let service = gnunet.service("cadet").connect().await?;		

		Ok( service.into() )
	}

	/// Returns a new, previously unused channel id.
	async fn next_free_channel( &self ) -> (u32, Receiver<ChannelMessage>) {
		// FIXME: This could be way more effecient.

		// We are only allowed to use ids that are above GNUNET_CADET_LOCAL_CHANNEL_ID_CLI
		let mut i = 0x80000001u32; //GNUNET_CADET_LOCAL_CHANNEL_ID_CLI + 1;
		let mut channels = self.shared.channels.lock().await;
		while channels.contains_key(&i) {
			i += 1;

			if i == 0 {
				panic!("no more channel ids")
			}
		}

		let (tx, rx) = channel::unbounded::<ChannelMessage>();
		channels.insert( i, tx );

		( i, rx )
	}

	/// Starts receiving messages.
	/// This function needs a way to spawn a future, because it will need to run an async loop.
	/// 
	/// # Arguments
	/// `spawn` - The spawn future.
	/// `on_error` - A closure that will be called every time an error occurs with the channel.
	/// 
	/// # Example
	/// ```
	/// use gnunet::{self, cadet, crypto::HashCode};
	/// use tokio;
	/// 
	/// #[tokio::main]
	/// async fn main() {
	/// 	let port = HashCode::generate("my-port".as_bytes());
	/// 	let address = PublicKey::from_string("A base32 encoded string of a public key here...").unwrap();
	/// 
	/// 	let service = cadet::Handle::connect( gnunet::Handle::default() ).unwrap();
	/// 	let channel = service.channel_connect( &address, &port ).await.unwrap();
	/// 
	/// 	channel.listen( |f| tokio::spawn(f), |e| {
	/// 		eprintln!("Error in cadet channel: {}", e);
	/// 	});
	/// }
	/// ```
	pub async fn listen<S,E>( &self, spawn: S, on_error: E ) where
		S: FnOnce( Pin<Box<dyn Future<Output=()> + Send>> ),
		E: Fn( crate::Error ) + Send + Sync + 'static
	{
		// This is safe because this cadet handle will only be used to read.
		let service = unsafe { self.inner.lock().await.clone() };
		let shared = self.shared.clone();

		let future: Pin<Box<dyn Future<Output=()> + Send>> = Box::pin( Self::receive_loop( service, shared, on_error ) );
		spawn( future );
	}

	/// Can be spawned to start received messages for the cadet service.
	/// Running this loop allocates the received messages to the designated channels
	async fn receive_loop<E>( service_: service::Handle, shared_: Arc<SharedData>, on_error: E ) where
		E: Fn( crate::Error )
	{
		while shared_.run_flag.load( Ordering::Relaxed ) == true {
			let shared = shared_.clone();
			let mut service = unsafe { service_.clone() };

			let result: error::Result<()> = async {
				let header = service.read_header().await?;
				
				match header.type_ as _ {
					GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK => {
						let channel_id = service.read_u32().await?;

						let channels = shared.channels.lock().await;
						match channels.get( &channel_id ) {
							None => eprintln!("Cadet service received ack for unknown channel with id {}", channel_id ),
							Some( sender ) => {
								sender.send( ChannelMessage::Ack ).await.unwrap();
							}
						}
					},
					GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY => {
						let channel_id = service.read_u32().await?;

						let channels = shared.channels.lock().await;
						match channels.get( &channel_id ) {
							None => eprintln!("Cadet service received destroy message for unknown channel with id {}", channel_id ),
							Some( sender ) => {
								sender.send( ChannelMessage::Destroy ).await.unwrap();
							}
						}
					}
					GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA => {
						let channel_id = service.read_u32().await?;
						let priority_flags = service.read_u32().await?;
						let payload = service.read_bytes( header.size as usize - 4 - 4 - 4 ).await?;

						let message = ChannelMessagePayload { priority_flags, payload };

						// Forward message to the designated channel
						let channels = shared.channels.lock().await;
						match channels.get( &channel_id ) {
							None => eprintln!("Cadet service received message for unknown channel with id {}", channel_id ),
							Some( sender ) => {
								sender.send( ChannelMessage::Payload( message ) ).await.unwrap();
							}
						}
					},
					GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE => {
						let result = service.read_result( header.size - 4 ).await;

						match result {
							Err(e) => on_error( e ),
							Ok(()) => {}
						}
					},
					other => eprintln!("Unexpected message received from cadet service: {}.", other)
				}

				Ok(())
			}.await;

			match result {
				Err(e) => {
					panic!("Error received in cadet receive loop: {}", e)
				},
				Ok(()) => {}
			}
		}
	}
}

impl From<crate::service::Handle> for Handle {
	fn from( handle: crate::service::Handle ) -> Self {
		Self {
			inner: Arc::new( Mutex::new( handle ) ),
			shared: Arc::new( SharedData {
				run_flag: AtomicBool::new( true ),
				channels: Mutex::new( HashMap::new() )
			})
		}
	}
}



impl fmt::Display for PrematureDestroyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "destruction message received before ack" )
	}
}

impl std::error::Error for PrematureDestroyError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}