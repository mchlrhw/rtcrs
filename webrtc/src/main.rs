use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread;

use env_logger;
use failure::Error;
use log::{debug, trace};
use pnet::datalink;

use sdp;

const MTU: usize = 1500;

fn udp_listener(address: IpAddr) -> Result<SocketAddr, Error> {
    debug!("Starting UDP listener on {}", address);

    let socket = UdpSocket::bind(format!("{}:0", address))?;
    let local_addr = socket.local_addr()?;
    trace!(
        "Socket bound on {} at {}",
        local_addr.ip(),
        local_addr.port()
    );

    thread::spawn(move || {
        let mut buf = [0; MTU];
        // TODO: remove unwrap
        let (bytes_rcvd, src_addr) = socket.recv_from(&mut buf).unwrap();
        trace!("Received {} bytes from {}", bytes_rcvd, src_addr);
    });

    Ok(local_addr)
}

fn main() {
    env_logger::init();

    let interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ips)
        .filter(|a| a.is_ipv4())
        .map(|a| a.ip())
        .collect();

    for interface in interfaces {
        match udp_listener(interface) {
            Ok(_) => debug!("Bind succeeded"),
            Err(_) => debug!("Bind failed"),
        }
    }

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
    .with_attributes(vec![
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
        sdp::Attribute::value("mid", "video"),
        sdp::Attribute::property("recvonly"),
        sdp::Attribute::value("ice-ufrag", "YKBo"),
        sdp::Attribute::value("ice-pwd", "TTlUG2PZn1bXg4vzBzVBHnTz"),
        sdp::Attribute::value("ice-options", "renomination"),
        sdp::Attribute::property("rtcp-mux"),
        sdp::Attribute::property("rtcp-rsize"),
    ]);

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
            sdp::Attribute::value("group", "BUNDLE video"),
        ],
    ).and_media_description(video_description);

    debug!("{:?}", session_description);
}
