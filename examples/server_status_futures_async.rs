use std::net::{SocketAddr, TcpListener};

use example_helpers::async_handle_connection_with_errors;
use futures::executor;
use futures_net::TcpStream;
use protocraft_framework::defaults::{
    Compression, asynchronous::futures::AsyncDefaultStreamProvider,
};

async fn handle_connection(read_stream: TcpStream, write_stream: TcpStream, socket: SocketAddr) {
    println!("Accepted connection: {}", socket);
    let provider =
        AsyncDefaultStreamProvider::new(read_stream, write_stream, Compression::default(), 4096);
    if let Err(err) = async_handle_connection_with_errors(provider).await {
        println!("Error: {:?}", err);
    }
    println!("Closed connection: {}", socket);
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565").expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener.accept().expect("Failed to accept connection");
        let other_stream = stream.try_clone().expect("Failed to clone the stream.");
        executor::block_on(handle_connection(
            stream.try_into().unwrap(),
            other_stream.try_into().unwrap(),
            socket,
        ))
    }
}
