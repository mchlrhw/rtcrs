use std::io::BufRead;

use anyhow::Error;
use fehler::throws;
use log::debug;
use tokio::time;

async fn block_forever() {
    loop {
        time::sleep(time::Duration::from_secs(1)).await;
    }
}

#[throws]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();

    let peer_connection = webrtc::PeerConnection::new();

    let mut offer_b64 = String::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        offer_b64.push_str(&line);
    }

    let offer = sdp::SessionDescription::from_base64(&offer_b64)?;
    debug!("{}", offer);

    let peer_connection = peer_connection.set_remote_description(offer);

    let answer = peer_connection.create_answer();
    let peer_connection = peer_connection.set_local_description(answer).await;

    let answer = sdp::SessionDescriptionWrapper::new_answer(
        &peer_connection.local_description().to_string(),
    );
    println!("{}", base64::encode(serde_json::to_string(&answer)?));

    block_forever().await;
}
