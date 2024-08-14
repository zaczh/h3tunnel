use anyhow::{anyhow, Result};
use clap::Parser;
use log::{error, info, trace, warn};
use s2n_quic::stream::BidirectionalStream;
use s2n_quic::{client::Connect, Client};
use std::net::SocketAddr;
use std::str::FromStr;
use std::{net::ToSocketAddrs, path::PathBuf, sync::Arc};
use tokio::net::UdpSocket;
use tokio::time::Duration;
use udp_stream::UdpStream;
use url::Url;
mod common;

static IDEL_TIMEOUT: Duration = Duration::from_secs(30);

/// Wireguard over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// The remote server address, example: `https://example.com:8443`
    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Local listen address and port, example: `--listen 0.0.0.0:3242`
    #[clap(short = 'l', long = "listen")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let options = Opt::parse();
    let listen_address = options.listen;
    let local_socket_addr = listen_address.parse::<SocketAddr>().unwrap();
    let sock = create_reused_udp_socket(local_socket_addr);
    let r = Arc::new(sock);
    let w = r.clone();

    let options = Opt::parse();
    let url = options.url;
    let url_host = if let Some(host) = options.host {
        host
    } else {
        strip_ipv6_brackets(url.host_str().unwrap()).to_string()
    };

    let remote = (
        strip_ipv6_brackets(url.host_str().unwrap()),
        url.port_or_known_default().unwrap_or(443),
    )
        .to_socket_addrs()
        .unwrap()
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))
        .unwrap();

    trace!("remote: {remote}, host: {url_host}");

    let cert_content = match options.ca {
        Some(cert_path) => {
            std::fs::read_to_string(cert_path.to_str().unwrap().to_string()).unwrap()
        }
        _ => include_str!("../certs/cert.pem").to_string(),
    };

    let limits = s2n_quic::provider::limits::Limits::new()
        .with_max_idle_timeout(IDEL_TIMEOUT)
        .unwrap();

    let local_socket_addr = if remote.is_ipv4() {
        SocketAddr::from_str("0.0.0.0:0").unwrap()
    } else {
        SocketAddr::from_str("[::]:0").unwrap()
    };

    let io = s2n_quic::provider::io::Default::builder()
        .with_receive_address(local_socket_addr)
        .unwrap()
        .build()
        .unwrap();

    let client = Client::builder()
        .with_tls(cert_content.as_str())
        .unwrap()
        .with_io(io)
        .unwrap()
        .with_limits(limits)
        .unwrap()
        .start()
        .unwrap();
    trace!("started");

    let connect = Connect::new(remote).with_server_name(url_host);
    let mut connection = match client.connect(connect).await {
        Ok(c) => c,
        Err(e) => {
            panic!("failed to connect: {e}");
        }
    };
    trace!("connected");
    let connection_handle = connection.handle();

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true).unwrap();

    loop {
        // Receive data from the local udp listener
        trace!("Receiving on local address");
        let mut buf = [0; 9000]; // jumbo frame
        let (n, src) = match w.recv_from(&mut buf).await {
            Ok(d) => d,
            Err(e) => {
                error!("Receiving error: {e}");
                break;
            }
        };
        let data: bytes::Bytes = bytes::Bytes::copy_from_slice(&buf[..n]);
        let local = w.local_addr().unwrap();
        trace!("accept from: {local}, to: {remote}, src: {src}");
        let sock = create_reused_udp_socket(local);
        trace!("socket created");
        sock.connect(src).await.unwrap();
        trace!("socket connected");
        let udp_stream = UdpStream::from_tokio(sock).await.unwrap();
        let mut connection_handle = connection_handle.clone();
        tokio::spawn(async move {
            trace!("stream handling thread created");
            let stream = match connection_handle.open_bidirectional_stream().await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("failed to open stream: {e}");
                    return;
                }
            };
            trace!("stream opened");
            let _ = handle_stream(stream, udp_stream, data).await;
        });
    }

    trace!("main exit");
    Ok(())
}

async fn handle_stream(
    mut h3_stream: BidirectionalStream,
    mut udp_stream: UdpStream,
    data: bytes::Bytes,
) -> Result<()> {
    let id = h3_stream.id();
    trace!("[stream: {id}] connection established");

    // send initial data
    let _ = h3_stream.send_data(data);

    // send and receive data
    let _ = tokio::io::copy_bidirectional_with_sizes(
        &mut h3_stream,
        &mut udp_stream,
        common::SOCKET_BUFFER_SIZE,
        common::SOCKET_BUFFER_SIZE,
    )
    .await;

    info!("[stream: {id}] stream closed");
    Ok(())
}

fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:443/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

// we use SO_REUSEADDR socket option to handle single udp connection,
// to avoid send local peer address to remote server.
// https://blog.cloudflare.com/everything-you-ever-wanted-to-know-about-udp-sockets-but-were-afraid-to-ask-part-1
pub fn create_reused_udp_socket(addr: SocketAddr) -> tokio::net::UdpSocket {
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )
    .unwrap();
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_nonblocking(true);

    const BUF_SIZES: [usize; 7] = [64usize, 32usize, 16usize, 8usize, 4usize, 2usize, 1usize];
    for size in BUF_SIZES.iter() {
        if let Err(err) = socket.set_recv_buffer_size(size * 1024 * 1024) {
            warn!(
                "Cannot increase UDP server recv buffer to {} Mib: {}",
                size, err
            );
            warn!("This is not fatal, but can lead to packet loss if you have too much throughput. You must monitor packet loss in this case");
            continue;
        }

        if *size != BUF_SIZES[0] {
            info!("Increased UDP server recv buffer to {} Mib", size);
        }

        break;
    }

    for size in BUF_SIZES.iter() {
        if let Err(err) = socket.set_send_buffer_size(size * 1024 * 1024) {
            warn!(
                "Cannot increase UDP server send buffer to {} Mib: {}",
                size, err
            );
            warn!("This is not fatal, but can lead to packet loss if you have too much throughput. You must monitor packet loss in this case");
            continue;
        }

        if *size != BUF_SIZES[0] {
            info!("Increased UDP server send buffer to {} Mib", size);
        }
        break;
    }

    socket.bind(&addr.into()).unwrap();
    UdpSocket::from_std(socket.into()).unwrap()
}
