use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use example_helpers::handle_connection_with_errors;
use protocraft_framework::{
    defaults::sync::DefaultStreamProvider,
    error::{ReadError, WriteError},
};

#[allow(unused)]
#[derive(Debug)]
enum Error {
    Read(ReadError<std::io::Error>),
    Write(WriteError<std::io::Error>),
}

fn handle_connection(stream: TcpStream, socket: SocketAddr) {
    println!("Accepted connection: {}", socket);
    let other_stream = stream.try_clone().expect("Failed to clone stream");
    let provider = DefaultStreamProvider::new(stream, other_stream);
    if let Err(err) = handle_connection_with_errors(provider) {
        println!("Error: {:?}", err);
    }
    println!("Disconnected connection: {}", socket);
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565").expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener.accept().expect("Failed to accept connection");
        // Inefficient, but shows can be delegated to a seperate thread
        thread::spawn(move || handle_connection(stream, socket));
    }
}
