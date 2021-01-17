use std::{
    convert::{TryFrom, TryInto},
    default::Default,
    iter::FromIterator,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use fehler::{throw, throws};
use log::{debug, trace, warn};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric1, char, crlf, digit1, none_of, one_of},
    combinator::{all_consuming, map, map_res, opt, recognize},
    multi::{count, many0, many1, many_m_n},
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};
use nom_locate::LocatedSpan;
use pnet::datalink;
use rand::{self, seq::SliceRandom};
use tokio::{net::UdpSocket, task};

const MTU: usize = 1500;
const ICE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind")]
    BindFailed { source: std::io::Error },
    #[error("invalid candidate attribute: {0}")]
    InvalidCandidate(String),
    #[error("unsupported candidate type: {0}")]
    UnsupportedCandidateType(String),
    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),
}

type Span<'a> = LocatedSpan<&'a str>;

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
async fn udp_listener(address: &IpAddr, key: &str) -> SocketAddr {
    debug!("Starting UDP listener on {}", address);

    let socket = UdpSocket::bind(format!("{}:0", address))
        .await
        .map_err(|source| Error::BindFailed { source })?;
    let local_addr = socket.local_addr().unwrap();
    debug!("Socket bound to {}", local_addr);

    let key = key.to_string();
    task::spawn(async move {
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

            socket.send_to(&reply, src_addr).await.unwrap();
        }
    });

    local_addr
}

struct Foundation(String);

fn foundation(input: Span) -> IResult<Span, Foundation> {
    map(
        terminated(many_m_n(1, 32, one_of(ICE_CHARS)), char(' ')),
        |chars| Foundation(String::from_iter(&chars)),
    )(input)
}

struct ComponentId(u16);

fn component_id(input: Span) -> IResult<Span, ComponentId> {
    let (remainder, id) = map_res(
        terminated(recognize(many_m_n(1, 5, digit1)), char(' ')),
        |digits: Span| (*digits.fragment()).parse(),
    )(input)?;

    Ok((remainder, ComponentId(id)))
}

//  token       =  1*(alphanum / "-" / "." / "!" / "%" / "*"
//                 / "_" / "+" / "`" / "'" / "~" )
//
// https://tools.ietf.org/html/rfc3261#section-25.1
fn token(input: Span) -> IResult<Span, Span> {
    recognize(many1(alt((
        alphanumeric1,
        recognize(many1(one_of("-.!%*_+`'~"))),
    ))))(input)
}

#[derive(Clone, Debug, PartialEq)]
enum Transport {
    Udp,
    Tcp,
}

impl FromStr for Transport {
    type Err = Error;

    #[throws]
    fn from_str(token: &str) -> Self {
        match token {
            "udp" | "UDP" => Self::Udp,
            "tcp" | "TCP" => Self::Tcp,
            _ => throw!(Error::UnsupportedTransport(token.to_string())),
        }
    }
}

fn transport(input: Span) -> IResult<Span, Transport> {
    map_res(terminated(token, char(' ')), |token: Span| {
        (*token.fragment()).parse()
    })(input)
}

struct Priority(u32);

fn priority(input: Span) -> IResult<Span, Priority> {
    let (remainder, priority) = map_res(
        terminated(recognize(many_m_n(1, 10, digit1)), char(' ')),
        |digits: Span| (*digits.fragment()).parse(),
    )(input)?;

    Ok((remainder, Priority(priority)))
}

fn ipv4_address(input: Span) -> IResult<Span, IpAddr> {
    map_res(
        recognize(pair(count(terminated(digit1, char('.')), 3), digit1)),
        |addr: Span| (*addr.fragment()).parse(),
    )(input)
}

type Port = u16;

fn port(input: Span) -> IResult<Span, Port> {
    map_res(recognize(many_m_n(1, 5, digit1)), |digits: Span| {
        (*digits.fragment()).parse()
    })(input)
}

fn connection_address_and_port(input: Span) -> IResult<Span, SocketAddr> {
    map(
        pair(
            terminated(ipv4_address, char(' ')),
            terminated(port, char(' ')),
        ),
        SocketAddr::from,
    )(input)
}

#[derive(Clone, Debug, PartialEq)]
enum CandidateType {
    Host,
    ServerReflexive,
    Relayed,
    PeerReflexive,
}

impl FromStr for CandidateType {
    type Err = Error;

    #[throws]
    fn from_str(token: &str) -> Self {
        match token {
            "host" => Self::Host,
            "srflx" => Self::ServerReflexive,
            "relay" => Self::Relayed,
            "prflx" => Self::PeerReflexive,
            _ => throw!(Error::UnsupportedCandidateType(token.to_string())),
        }
    }
}

fn candidate_type(input: Span) -> IResult<Span, CandidateType> {
    map_res(preceded(tag("typ "), token), |token: Span| {
        (*token.fragment()).parse()
    })(input)
}

fn related_address_and_port(input: Span) -> IResult<Span, SocketAddr> {
    map(
        pair(
            preceded(tag(" raddr "), ipv4_address),
            preceded(tag(" rport "), port),
        ),
        SocketAddr::from,
    )(input)
}

struct ExtensionAttribute(String, String);

fn extension_attribute(input: Span) -> IResult<Span, ExtensionAttribute> {
    map(
        pair(
            preceded(char(' '), many1(none_of(" \r\n"))),
            preceded(char(' '), many1(none_of(" \r\n"))),
        ),
        |(name, value)| ExtensionAttribute(String::from_iter(&name), String::from_iter(&value)),
    )(input)
}

trait Candidate {}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalCandidate {
    address: SocketAddr,
    ty: CandidateType,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RemoteCandidate {
    address: SocketAddr,
    ty: CandidateType,
}

type RemoteCandidateArgs = (
    Foundation,
    ComponentId,
    Transport,
    Priority,
    SocketAddr,
    CandidateType,
    Option<SocketAddr>,
    Vec<ExtensionAttribute>,
);

impl RemoteCandidate {
    fn from_tuple(args: RemoteCandidateArgs) -> Self {
        Self {
            address: args.4,
            ty: args.5,
        }
    }
}

//   candidate-attribute   = "candidate" ":" foundation SP component-id SP
//                           transport SP
//                           priority SP
//                           connection-address SP     ;from RFC 4566
//                           port         ;port from RFC 4566
//                           SP cand-type
//                           [SP rel-addr]
//                           [SP rel-port]
//                           *(SP extension-att-name SP
//                                extension-att-value)
//
//   foundation            = 1*32ice-char
//   component-id          = 1*5DIGIT
//   transport             = "UDP" / transport-extension
//   transport-extension   = token              ; from RFC 3261
//   priority              = 1*10DIGIT
//   cand-type             = "typ" SP candidate-types
//   candidate-types       = "host" / "srflx" / "prflx" / "relay" / token
//   rel-addr              = "raddr" SP connection-address
//   rel-port              = "rport" SP port
//   extension-att-name    = byte-string    ;from RFC 4566
//   extension-att-value   = byte-string
//   ice-char              = ALPHA / DIGIT / "+" / "/"
//
// https://tools.ietf.org/html/rfc5245#section-15.1
fn candidate(input: Span) -> IResult<Span, RemoteCandidate> {
    map(
        tuple((
            foundation,
            component_id,
            transport,
            priority,
            connection_address_and_port,
            candidate_type,
            opt(related_address_and_port),
            many0(extension_attribute),
        )),
        RemoteCandidate::from_tuple,
    )(input)
}

impl FromStr for RemoteCandidate {
    type Err = Error;

    #[throws(Error)]
    fn from_str(s: &str) -> Self {
        let input = Span::new(&s);
        let (_, candidate) = all_consuming(candidate)(input)
            .map_err(|err| Error::InvalidCandidate(err.to_string()))?;

        candidate
    }
}

fn candidate_attribute(input: Span) -> IResult<Span, RemoteCandidate> {
    delimited(tag("a=candidate:"), candidate, crlf)(input)
}

impl TryFrom<sdp::Attribute> for RemoteCandidate {
    type Error = Error;

    #[throws(Error)]
    fn try_from(attribute: sdp::Attribute) -> Self {
        let attr_string = attribute.to_string();
        let input = Span::new(&attr_string);
        let (_, candidate) = all_consuming(candidate_attribute)(input)
            .map_err(|err| Error::InvalidCandidate(err.to_string()))?;

        candidate
    }
}

impl Candidate for LocalCandidate {}
impl Candidate for RemoteCandidate {}

#[derive(Debug)]
pub struct Agent {
    username: String,
    password: String,
    local_addrs: Vec<IpAddr>,
    local_candidates: Vec<LocalCandidate>,
    remote_candidates: Vec<RemoteCandidate>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            username: rand_ice_string(4),
            password: rand_ice_string(22),
            local_addrs: get_local_addrs(),
            local_candidates: vec![],
            remote_candidates: vec![],
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

    #[throws]
    pub fn add_remote_candidate(&mut self, candidate_attribute: sdp::Attribute) {
        let candidate = candidate_attribute.try_into()?;
        self.remote_candidates.push(candidate);
    }

    pub async fn gather(&mut self) {
        for local_addr in &self.local_addrs {
            if let Ok(address) = udp_listener(local_addr, &self.password).await {
                let candidate = LocalCandidate {
                    ty: CandidateType::Host,
                    address,
                };
                self.local_candidates.push(candidate);

                break; // we only want one for now
            } else {
                warn!("Unable to gather host candidate on {}", local_addr);
            }
        }
    }

    pub fn candidate_attributes(&self) -> Vec<sdp::Attribute> {
        self.local_candidates
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[throws]
    fn remote_candidate_from_attribute() {
        let candidate_attribute = sdp::Attribute::Value("candidate".to_string(), "1853887674 2 udp 1518280447 47.61.61.61 36768 typ srflx raddr 192.168.0.196 rport 36768 generation 0".to_string());
        let _candidate: RemoteCandidate = candidate_attribute.try_into()?;
    }

    #[test]
    #[throws]
    fn remote_candidate_from_attribute_with_caps_transport() {
        let candidate_attribute = sdp::Attribute::Value(
            "candidate".to_string(),
            "3 2 UDP 1686052862 47.61.61.61 64346 typ srflx raddr 192.168.0.196 rport 64346"
                .to_string(),
        );
        let _candidate: RemoteCandidate = candidate_attribute.try_into()?;
    }

    #[test]
    #[throws]
    fn remote_candidate_from_str() {
        let candidate_string = "4 2 TCP 2105458942 10.10.10.10 9 typ host tcptype active";
        let _candidate: RemoteCandidate = candidate_string.parse()?;
    }
}
