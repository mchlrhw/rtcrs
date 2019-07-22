use std::default::Default;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};

use failure::Error;
use log::{debug, trace, warn};
use pnet::datalink;
use rand::{self, seq::SliceRandom};

use sdp;

const MTU: usize = 1500;
const ICE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/";

fn rand_ice_string(length: usize) -> String {
    let mut rng = &mut rand::thread_rng();
    let random_chars: Vec<u8> = ICE_CHARS
        .choose_multiple(&mut rng, length)
        .cloned()
        .collect();
    // SAFE: due to the fact that ICE_CHARS is entirely ASCII
    String::from_utf8(random_chars).unwrap()
}

fn udp_listener(address: IpAddr) -> Result<(SocketAddr, JoinHandle<()>), Error> {
    debug!("Starting UDP listener on {}", address);

    let socket = UdpSocket::bind(format!("{}:0", address))?;
    let local_addr = socket.local_addr()?;
    trace!(
        "Socket bound on {} at {}",
        local_addr.ip(),
        local_addr.port()
    );

    let handle = thread::spawn(move || {
        let mut buf = [0; MTU];
        trace!("Receiving on {:?}", socket.local_addr());
        let (bytes_rcvd, src_addr) = socket.recv_from(&mut buf).unwrap();
        trace!("Received {} bytes from {}", bytes_rcvd, src_addr);
    });

    Ok((local_addr, handle))
}

#[derive(Clone, Debug, PartialEq)]
struct Candidate {
    address: SocketAddr,
}

#[derive(Debug)]
pub struct Agent {
    username: String,
    password: String,
    candidates: Vec<Candidate>,
    thread_handles: Vec<JoinHandle<()>>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            username: rand_ice_string(4),
            password: rand_ice_string(22),
            candidates: vec![],
            thread_handles: vec![],
        }
    }
}

impl Agent {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> String {
        self.password.clone()
    }

    pub fn gather(&mut self) {
        let interfaces: Vec<_> = datalink::interfaces()
            .into_iter()
            .filter(|i| i.is_up() && !i.is_loopback())
            .flat_map(|i| i.ips)
            .filter(|a| a.is_ipv4())
            .map(|a| a.ip())
            .collect();

        for interface in interfaces {
            match udp_listener(interface) {
                Ok((address, handle)) => {
                    let candidate = Candidate { address };
                    self.candidates.push(candidate);
                    self.thread_handles.push(handle);
                }
                Err(_) => warn!("Unable to gather local candidate on {}", interface),
            }
        }
    }

    pub fn candidate_attributes(&self) -> Vec<sdp::Attribute> {
        self.candidates
            .clone()
            .into_iter()
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
    let priority = ((2_i64.pow(24)) * 126) + ((2_i64.pow(8)) * ip_precedence) + 256 - component_id;

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
