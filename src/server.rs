use anyhow::Result;
use clap::Parser;
use log::trace;
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::Server;
use std::{net::SocketAddr, path::PathBuf};
use udp_stream::UdpStream;
mod common;

/// Wireguard over QUIC server
#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Address to listen on
    #[clap(short = 'l', long = "listen", default_value = "[::1]:443")]
    listen: String,
    /// Forwarding target
    #[clap(short = 'f', long = "forward-to")]
    forward_to: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let options = Opt::parse();
    let (key_content, cert_content) = match (options.key, options.cert) {
        (Some(key_path), Some(cert_path)) => (
            std::fs::read_to_string(key_path.to_str().unwrap().to_string()).unwrap(),
            std::fs::read_to_string(cert_path.to_str().unwrap().to_string()).unwrap(),
        ),
        _ => (
            include_str!("../certs/cert.key.pem").to_string(),
            include_str!("../certs/cert.pem").to_string(),
        ),
    };

    let listen_address = options.listen;
    let local_socket_addr = listen_address.parse::<SocketAddr>().unwrap();

    let io = s2n_quic::provider::io::Default::builder()
        .with_receive_address(local_socket_addr)
        .unwrap()
        .build()
        .unwrap();

    let limits = s2n_quic::provider::limits::Limits::default();

    let congestion_controller = s2n_quic::provider::congestion_controller::Bbr::default();

    let mut server = Server::builder()
        .with_tls((cert_content.as_str(), key_content.as_str()))
        .unwrap()
        .with_io(io)
        .unwrap()
        .with_congestion_controller(congestion_controller)
        .unwrap()
        .with_limits(limits)
        .unwrap()
        .start()
        .unwrap();

    while let Some(mut connection) = server.accept().await {
        // spawn a new task for the connection
        tokio::spawn(async move {
            trace!("Connection accepted from {:?}", connection.remote_addr());
            while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                // spawn a new task for the stream
                tokio::spawn(async move {
                    trace!(
                        "Stream opened from {}",
                        stream.connection().remote_addr().unwrap()
                    );
                    let _ = handle_stream(stream).await;
                });
            }
        });
    }

    Ok(())
}

async fn handle_stream(mut h3_stream: BidirectionalStream) -> Result<()> {
    let id = h3_stream.id();
    trace!("[stream: {id}] stream accepted");
    let _ = h3_stream.connection().keep_alive(true);

    let opt = Opt::parse();
    let forward_to = opt.forward_to;
    let dst_socket: SocketAddr = forward_to.parse().unwrap();

    let mut udp_stream = UdpStream::connect(dst_socket).await.unwrap();

    // send and receive data
    let _ = tokio::io::copy_bidirectional_with_sizes(
        &mut h3_stream,
        &mut udp_stream,
        common::SOCKET_BUFFER_SIZE,
        common::SOCKET_BUFFER_SIZE,
    )
    .await;

    trace!("[stream: {id}] stream closed");
    Ok(())
}
