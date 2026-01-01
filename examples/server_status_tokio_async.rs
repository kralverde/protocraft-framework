use std::net::SocketAddr;

use example_helpers::async_handle_connection_with_errors;
use protocraft_framework::defaults::asynchronous::tokio::AsyncDefaultStreamProvider;
use tokio::net::{TcpListener, TcpStream};

async fn handle_connection(stream: TcpStream, socket: SocketAddr) {
    println!("Accepted connection: {}", socket);
    let (reader, writer) = stream.into_split();
    let provider = AsyncDefaultStreamProvider::new(reader, writer);
    if let Err(err) = async_handle_connection_with_errors(provider).await {
        println!("Error: {:?}", err);
    }
    println!("Closed connection: {}", socket);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565")
        .await
        .expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener
            .accept()
            .await
            .expect("Failed to accept connection");

        tokio::spawn(handle_connection(stream, socket));
    }
}
