use protocraft_framework::defaults::asynchronous::tokio::AsyncDefaultStreamProvider;
use tokio::net::{TcpListener, TcpStream};

async fn handle_connection(stream: TcpStream) {
    let (reader, writer) = stream.into_split();
    let provider = AsyncDefaultStreamProvider::new(reader, writer);
    if let Err(err) = example_helpers::handle_connection_with_errors(provider).await {
        println!("Error: {:?}", err);
    }
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
        println!("Accepted connection: {}", socket);

        tokio::spawn(handle_connection(stream));
    }
}
