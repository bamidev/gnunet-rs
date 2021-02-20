//! The Gnunet API handles its own execution.
//! You either run `GNUNET_PROGRAM_run`, which runs its own loop, or you run `GNUNET_SERVICE_run`, which does that also.
//! The Gnunet API control flow works by giving it closures that execute on specific events.
//! For example, you want to send a message, and a closure will be called upon completion.
//! This control flow is very useful because you don't want to be waiting on a lot of the tasks you'll be doing.
//! 
//! Nevertheless, it is still usefull to control the execution of your own program.
//! For those cases, this runtime can be used.
//! Also, the runtime enables the programmer to make use of Rust's async/await syntax.
//! All it does is that it runs the Gnunet loop on a seperate thread, and all related functions pass the code to that loop, which executes it.
//! 
//! TODO: Implement