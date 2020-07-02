use std::{
    default::Default,
    net::{IpAddr, SocketAddr},
};

use async_std::{net::UdpSocket, task};
use fehler::throws;
use log::{trace, warn};
use pnet::datalink;
use rand::{self, seq::SliceRandom};

const MTU: usize = 1500;
const ICE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("failed to bind")]
    BindError { source: std::io::Error },
}

fn rand_ice_string(length: usize) -> String {
    let mut rng = &mut rand::thread_rng();
    let random_chars: Vec<u8> = ICE_CHARS
        .choose_multiple(&mut rng, length)
        .cloned()
        .collect();
    // SAFE: due to the fact that ICE_CHARS is entirely ASCII
    String::from_utf8(random_chars).unwrap()
}

fn local_addrs() -> Vec<IpAddr> {
    datalink::interfaces()
        .into_iter()
        .flat_map(|i| {
            if i.is_up() && !i.is_loopback() {
                i.ips
            } else {
                vec![]
            }
        })
        .filter_map(|a| if a.is_ipv4() { Some(a.ip()) } else { None })
        .collect()
}

// #[throws]
// fn udp_listener(address: &IpAddr, key: &str) -> (SocketAddr, JoinHandle<()>) {
//     debug!("Starting UDP listener on {}", address);

//     let socket =
//         UdpSocket::bind(format!("{}:0", address)).map_err(|source| Error::BindError { source })?;
//     let local_addr = socket.local_addr().unwrap();
//     debug!("Socket bound to {}", local_addr);

//     let key = key.to_string();
//     let handle = thread::spawn(move || {
//         let local_addr = socket.local_addr().unwrap();
//         let mut buf = [0; MTU];
//         loop {
//             let (bytes_rcvd, src_addr) = socket.recv_from(&mut buf).unwrap();
//             trace!(
//                 "Received {} bytes from {} on {}: {:02X?}",
//                 bytes_rcvd,
//                 src_addr,
//                 local_addr,
//                 buf[..bytes_rcvd].to_vec()
//             );

//             let (_, message) = stun::message(&buf[..bytes_rcvd]).unwrap();
//             debug!("Received connectivity check: {:?}", message);

//             if message.header.method != stun::Method::Binding
//                 && message.header.class != stun::Class::Request
//             {
//                 continue;
//             }

//             let mut maybe_username = None;
//             for attribute in message.attributes {
//                 match attribute {
//                     stun::Attribute::Username(u) => {
//                         maybe_username = Some(u);
//                         break;
//                     }
//                     _ => continue,
//                 }
//             }

//             let username = match maybe_username {
//                 Some(u) => u,
//                 None => continue,
//             };

//             let reply = stun::Message::base(stun::Header {
//                 class: stun::Class::Success,
//                 method: stun::Method::Binding,
//                 length: 0,
//                 transaction_id: message.header.transaction_id,
//             })
//             .with_attributes(vec![
//                 stun::Attribute::username(username.as_str()),
//                 stun::Attribute::xor_mapped_address(src_addr.ip(), src_addr.port()),
//             ])
//             .with_message_integrity(key.as_ref())
//             .with_fingerprint();

//             trace!("Prepared reply: {:?}", reply);

//             let reply = reply.to_bytes();

//             trace!("Sending reply: {:02X?}", reply.to_vec());

//             socket.send_to(&reply, src_addr).unwrap();
//         }
//     });

//     (local_addr, handle)
// }

#[derive(Clone, Debug, PartialEq)]
struct LocalCandidate {
    address: SocketAddr,
}

async fn candidate_loop(socket: UdpSocket) {
    // TODO: Remove this unwrap.
    let local_addr = socket.local_addr().unwrap();
    let mut buf = [0; MTU];
    loop {
        let (bytes_rcvd, src_addr) = socket.recv_from(&mut buf).await.unwrap();
        trace!(
            "Received {} bytes from {} on {}: {:02X?}",
            bytes_rcvd,
            src_addr,
            local_addr,
            buf[..bytes_rcvd].to_vec()
        );
    }
}

impl LocalCandidate {
    #[throws]
    async fn bind(ip_addr: IpAddr) -> Self {
        let socket = UdpSocket::bind(format!("{}:0", ip_addr))
            .await
            .map_err(|source| Error::BindError { source })?;
        let address = socket
            .local_addr()
            .map_err(|source| Error::BindError { source })?;

        task::spawn(candidate_loop(socket));

        Self { address }
    }
}

#[derive(Debug)]
pub struct Agent {
    username: String,
    password: String,
    candidates: Vec<LocalCandidate>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            username: rand_ice_string(4),
            password: rand_ice_string(22),
            candidates: vec![],
        }
    }
}

impl Agent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> String {
        self.password.clone()
    }

    pub async fn gather(&mut self) {
        for ip_addr in local_addrs() {
            if let Ok(candidate) = LocalCandidate::bind(ip_addr).await {
                self.candidates.push(candidate);
            } else {
                warn!("Unable to gather local candidate on {}", ip_addr);
            }
        }
    }

    pub fn candidate_attributes(&self) -> Vec<sdp::Attribute> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(f, c)| encode_as_sdp(f, c.address))
            .collect()
    }
}

fn encode_as_sdp(foundation: usize, candidate: SocketAddr) -> sdp::Attribute {
    let component_id = 1; // RTP == 1

    let transport = "udp";

    let ip_precedence = 65535; // IPv4 only
    let priority = ((2_u64.pow(24)) * 126) + ((2_u64.pow(8)) * ip_precedence) + 256 - component_id;

    let v = format!(
        "{} {} {} {} {} {} typ host",
        foundation,
        component_id,
        transport,
        priority,
        candidate.ip(),
        candidate.port(),
    );
    sdp::Attribute::value("candidate", &v)
}
