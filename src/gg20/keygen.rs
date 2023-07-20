use crate::gg20::state_machine::keygen::{Keygen, LocalKey};
use anyhow::{anyhow, Context, Result};
use curv::elliptic::curves::Secp256k1;
use futures::StreamExt;
use round_based::async_runtime::AsyncProtocol;
use rustmodel::KeygenMember;

use crate::utils;

use crate::utils::sm_client::join_computation;

pub async fn start_keygen(
    request_id: &str,
    token: &str,
    address: &str,
    room: &str,
    t: u16,
    n: u16,
    name: &str,
) -> Result<(u16, LocalKey<Secp256k1>, Vec<KeygenMember>)> {
    let (party_id, incoming, outgoing) = join_computation(
        request_id,
        token,
        surf::Url::parse(address)?,
        &format!("{}-ecdsa", room),
        (1..(n + 1)).collect(),
        None,
        Some(name.to_string()),
    )
    .await
    .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(party_id, t, n)?;
    let local_share = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    Ok((
        party_id,
        local_share,
        utils::common::get_progress(request_id, token, surf::Url::parse(address)?, room)
            .await
            .members,
    ))
}
