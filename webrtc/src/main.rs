use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};

use env_logger;
use failure::Error;
use log::{debug, trace};
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

// TODO: create Candidate struct and return that instead of String
fn gather_candidates() -> (Vec<sdp::Attribute>, Vec<JoinHandle<()>>) {
    let interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ips)
        .filter(|a| a.is_ipv4())
        .map(|a| a.ip())
        .collect();

    let mut local_candidates = vec![];
    let mut join_handles = vec![];
    for interface in interfaces {
        match udp_listener(interface) {
            Ok((candidate, handle)) => {
                local_candidates.push(candidate);
                join_handles.push(handle);
            }
            Err(_) => continue,
        }
    }

    let attributes = local_candidates
        .into_iter()
        .enumerate()
        .map(|(i, v)| encode_as_sdp(i, v))
        .collect();

    (attributes, join_handles)
}

fn main() {
    env_logger::init();

    let ice_pwd = rand_ice_string(22);
    let ice_ufrag = rand_ice_string(4);

    let (mut candidates, join_handles) = gather_candidates();
    debug!("Local candidates: {:?}", candidates);

    let video_description = sdp::MediaDescription::base(sdp::Media {
        typ: sdp::MediaType::Video,
        port: 7,
        protocol: "RTP/SAVPF".to_owned(),
        format: "96 97".to_owned(),
    })
    .with_connection(sdp::Connection {
        network_type: "IN".to_owned(),
        address_type: "IP4".to_owned(),
        connection_address: "127.0.0.1".to_owned(),
    })
    .with_attributes({
        candidates.append(&mut vec![
            sdp::Attribute::value("rtpmap", "96 VP8/90000"),
            sdp::Attribute::value("rtpmap", "97 rtx/90000"),
            sdp::Attribute::value("fmtp", "97 apt=96"),
            sdp::Attribute::value("ftcp-fb", "96 goog-remb"),
            sdp::Attribute::value("ftcp-fb", "96 ccm fir"),
            sdp::Attribute::value("ftcp-fb", "96 nack"),
            sdp::Attribute::value("ftcp-fb", "96 nack pli"),
            sdp::Attribute::value("extmap", "2 urn:ietf:params:rtp-hdrext:toffset"),
            sdp::Attribute::value(
                "extmap",
                "3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            ),
            sdp::Attribute::value("extmap", "4 urn:3gpp:video-orientation"),
            sdp::Attribute::value("setup", "active"),
            sdp::Attribute::value("mid", "0"),
            sdp::Attribute::property("sendonly"),
            sdp::Attribute::value("ice-ufrag", &ice_ufrag),
            sdp::Attribute::value("ice-pwd", &ice_pwd),
            sdp::Attribute::value("ice-options", "renomination"),
            sdp::Attribute::property("rtcp-mux"),
            sdp::Attribute::property("rtcp-rsize"),
        ]);

        candidates
    });

    let session_description = sdp::SessionDescription::base(
        sdp::Version(0),
        sdp::Origin {
            username: "rtcrs".to_owned(),
            session_id: 1_433_832_402_044_130_222,
            session_version: 1,
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            unicast_address: "127.0.0.1".to_owned(),
        },
        sdp::SessionName("-".to_owned()),
        sdp::TimeDescription::base(
            sdp::Timing {
                start_time: 0,
                stop_time: 0,
            },
        ),
    ).with_attributes(
        vec![
            sdp::Attribute::property("ice-lite"),
            sdp::Attribute::value("fingerprint", "sha-512 4E:DD:25:41:95:51:85:B6:6A:29:42:FF:56:5B:41:47:2C:6C:67:36:7D:97:91:5A:65:C7:E1:76:1B:6E:D3:22:45:B4:9F:DF:EA:93:FF:20:F4:CB:A8:53:AF:50:DA:87:5A:C5:4C:5B:F6:4C:50:DC:D9:29:A3:C0:19:7A:17:48"),
            sdp::Attribute::value("msid-semantic", " WMS *"),
            sdp::Attribute::value("group", "BUNDLE 0"),
        ],
    ).and_media_description(video_description);

    print!("{}", session_description);

    for handle in join_handles {
        handle.join().unwrap();
    }
}
