use env_logger;
use log::info;

use sdp;

fn main() {
    env_logger::init();

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
        sdp::Attribute::Value("rtpmap".to_owned(), "96 VP8/90000".to_owned()),
        sdp::Attribute::Value("rtpmap".to_owned(), "97 rtx/90000".to_owned()),
        sdp::Attribute::Value("fmtp".to_owned(), "97 apt=96".to_owned()),
        sdp::Attribute::Value("ftcp-fb".to_owned(), "96 goog-remb".to_owned()),
        sdp::Attribute::Value("ftcp-fb".to_owned(), "96 ccm fir".to_owned()),
        sdp::Attribute::Value("ftcp-fb".to_owned(), "96 nack".to_owned()),
        sdp::Attribute::Value("ftcp-fb".to_owned(), "96 nack pli".to_owned()),
        sdp::Attribute::Value(
            "extmap".to_owned(),
            "2 urn:ietf:params:rtp-hdrext:toffset".to_owned(),
        ),
        sdp::Attribute::Value(
            "extmap".to_owned(),
            "3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_owned(),
        ),
        sdp::Attribute::Value(
            "extmap".to_owned(),
            "4 urn:3gpp:video-orientation".to_owned(),
        ),
        sdp::Attribute::Value("setup".to_owned(), "active".to_owned()),
        sdp::Attribute::Value("mid".to_owned(), "video".to_owned()),
        sdp::Attribute::Property("recvonly".to_owned()),
        sdp::Attribute::Value("ice-ufrag".to_owned(), "YKBo".to_owned()),
        sdp::Attribute::Value("ice-pwd".to_owned(), "TTlUG2PZn1bXg4vzBzVBHnTz".to_owned()),
        sdp::Attribute::Value("ice-options".to_owned(), "renomination".to_owned()),
        sdp::Attribute::Property("rtcp-mux".to_owned()),
        sdp::Attribute::Property("rtcp-rsize".to_owned()),
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
        sdp::TimeDescription {
            timing: sdp::Timing {
                start_time: 0,
                stop_time: 0,
            },
            repeat_times: vec![],
        },
    ).with_attributes(
        vec![
            sdp::Attribute::Property("ice-lite".to_owned()),
            sdp::Attribute::Value("fingerprint".to_owned(), "sha-512 4E:DD:25:41:95:51:85:B6:6A:29:42:FF:56:5B:41:47:2C:6C:67:36:7D:97:91:5A:65:C7:E1:76:1B:6E:D3:22:45:B4:9F:DF:EA:93:FF:20:F4:CB:A8:53:AF:50:DA:87:5A:C5:4C:5B:F6:4C:50:DC:D9:29:A3:C0:19:7A:17:48".to_owned()),
            sdp::Attribute::Value("msid-semantic".to_owned(), " WMS *".to_owned()),
            sdp::Attribute::Value("group".to_owned(), "BUNDLE video".to_owned()),
        ],
    ).with_media_descriptions(
        vec![video_description],
    );

    info!("{:?}", session_description);
}
