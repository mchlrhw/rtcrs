use std::{
    default::Default,
    net::{IpAddr, SocketAddr, UdpSocket},
    thread::{self, JoinHandle},
};

use fehler::throws;
use log::{debug, trace, warn};
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

fn get_local_addrs() -> Vec<IpAddr> {
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

#[throws]
fn udp_listener(address: &IpAddr, key: &str) -> (SocketAddr, JoinHandle<()>) {
    debug!("Starting UDP listener on {}", address);

    let socket =
        UdpSocket::bind(format!("{}:0", address)).map_err(|source| Error::BindError { source })?;
    let local_addr = socket.local_addr().unwrap();
    debug!("Socket bound to {}", local_addr);

    let key = key.to_string();
    let handle = thread::spawn(move || {
        let local_addr = socket.local_addr().unwrap();
        let mut buf = [0; MTU];
        loop {
            let (bytes_rcvd, src_addr) = socket.recv_from(&mut buf).unwrap();
            trace!(
                "Received {} bytes from {} on {}: {:02X?}",
                bytes_rcvd,
                src_addr,
                local_addr,
                buf[..bytes_rcvd].to_vec()
            );

            let (_, message) = stun::message(&buf[..bytes_rcvd]).unwrap();
            debug!("Received connectivity check: {:?}", message);

            if message.header.method != stun::Method::Binding
                && message.header.class != stun::Class::Request
            {
                continue;
            }

            let mut maybe_username = None;
            for attribute in message.attributes {
                match attribute {
                    stun::Attribute::Username(u) => {
                        maybe_username = Some(u);
                        break;
                    }
                    _ => continue,
                }
            }

            let username = match maybe_username {
                Some(u) => u,
                None => continue,
            };

            let reply = stun::Message::base(stun::Header::new(
                stun::Method::Binding,
                stun::Class::Success,
                message.header.transaction_id,
            ))
            .with_attributes(vec![
                stun::Attribute::username(username.as_str()),
                stun::Attribute::xor_mapped_address(src_addr.ip(), src_addr.port()),
            ])
            .with_message_integrity(key.as_ref())
            .with_fingerprint();

            trace!("Prepared reply: {:?}", reply);

            let reply = reply.to_bytes();

            trace!("Sending reply: {:02X?}", reply.to_vec());

            socket.send_to(&reply, src_addr).unwrap();
        }
    });

    (local_addr, handle)
}

#[derive(Clone, Debug, PartialEq)]
struct Candidate {
    address: SocketAddr,
}

#[derive(Debug)]
pub struct Agent {
    username: String,
    password: String,
    local_addrs: Vec<IpAddr>,
    candidates: Vec<Candidate>,
    thread_handles: Vec<JoinHandle<()>>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            username: rand_ice_string(4),
            password: rand_ice_string(22),
            local_addrs: get_local_addrs(),
            candidates: vec![],
            thread_handles: vec![],
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

    pub fn gather(&mut self) {
        for local_addr in &self.local_addrs {
            if let Ok((address, handle)) = udp_listener(local_addr, &self.password) {
                let candidate = Candidate { address };
                self.candidates.push(candidate);
                self.thread_handles.push(handle);

                break; // we only want one for now
            } else {
                warn!("Unable to gather local candidate on {}", local_addr);
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

    pub fn wait_till_completion(self) {
        for handle in self.thread_handles {
            handle.join().unwrap();
        }
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
