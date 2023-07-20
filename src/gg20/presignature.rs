use anyhow::{anyhow, Context, Result};
use curv::elliptic::curves::Secp256k1;
use futures::StreamExt;
use round_based::async_runtime::AsyncProtocol;

use crate::gg20::state_machine::keygen::LocalKey;
use crate::gg20::state_machine::sign::{CompletedOfflineStage, OfflineStage};
use crate::utils::sm_client::join_computation;

pub async fn generate_offline_signing(
    request_id: &str,
    token: &str,
    local_share: &LocalKey<Secp256k1>,
    address: &str,
    room: &str,
    party_id: u16,
    parties: Vec<u16>,
) -> Result<CompletedOfflineStage> {
    println!(
        "requestId={} start offline for party: {} in group {:?} room {}",
        request_id,
        party_id,
        parties.clone(),
        room.clone()
    );

    let (party_id, incoming, outgoing) = join_computation(
        request_id,
        token,
        surf::Url::parse(address).unwrap(),
        &format!("{}-offline", room),
        parties.clone(),
        Some(party_id),
        None,
    )
    .await
    .context("join offline computation")?;

    println!(
        "requestId={} offline t{} for parties {:?}",
        request_id, party_id, parties
    );

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(party_id, parties.clone(), local_share.clone())?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| {
            anyhow!(
                "offline generation failed for parties {:?} with error: {}",
                parties,
                e
            )
        })?;
    println!(
        "requestId={} completed offline {} for parties {:?}",
        request_id, party_id, parties
    );
    Ok(completed_offline_stage)
}
