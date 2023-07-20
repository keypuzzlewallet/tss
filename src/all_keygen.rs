use anyhow::Result;
use futures::StreamExt;

use crate::gg20;
use crate::utils::common::{EcdsaLocalKeyData, EddsaLocalKeyData};
use crate::{
    t_ed25519::presignature,
    utils::common::{self, EcdsaOfflineResult, KeygenResult},
};

pub async fn keygen_and_offline(
    request_id: &str,
    token: &str,
    rust_address: &str,
    rust_room: &str,
    rust_t: u16,
    rust_n: u16,
    max_nonce_per_refresh: u16,
    rust_name: &str,
) -> Result<KeygenResult> {
    // keygen ecdsa
    let (party_id, ecdsa_local_key, members) = gg20::keygen::start_keygen(
        request_id,
        token,
        rust_address,
        rust_room,
        rust_t,
        rust_n,
        rust_name,
    )
    .await?;

    let all_parties: Vec<u16> = (1..(rust_n + 1)).collect();
    // find all subsets in all_parties that size is t
    let all_subsets_parties: Vec<Vec<u16>> = common::powerset(all_parties.as_slice())
        .into_iter()
        .filter(|subset| subset.len() == (rust_t + 1) as usize && subset.contains(&party_id))
        .collect();
    println!(
        "requestId={} ecdsa - party: {} will pair with {:?}",
        request_id,
        party_id,
        all_subsets_parties.clone()
    );

    let mut ecdsa_offline_data: Vec<EcdsaOfflineResult> = vec![];
    let mut progress = 0;
    for mut parties in all_subsets_parties.clone() {
        parties.sort();
        let completed_offline = crate::gg20::presignature::generate_offline_signing(
            request_id,
            token,
            &ecdsa_local_key,
            rust_address,
            format!(
                "{}-parties-{}",
                rust_room,
                parties
                    .clone()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join("_")
            )
            .as_str(),
            party_id,
            parties.clone(),
        )
        .await?;
        ecdsa_offline_data.push(EcdsaOfflineResult {
            parties: parties.clone(),
            completed_offline,
        });
        progress = progress + 1;
        println!(
            "requestId={} progress: {}%",
            request_id,
            progress * 100 / all_subsets_parties.clone().len()
        );
    }

    // keygen eddsa
    println!(
        "requestId={} start eddsa keygen party: {}",
        request_id, party_id
    );
    let eddsa_local_key = crate::t_ed25519::keygen::start_keygen(
        request_id,
        token,
        rust_address,
        rust_room,
        rust_t,
        rust_n,
        party_id,
    )
    .await?;

    println!(
        "requestId={} eddsa - party: {} will pair with {:?}",
        request_id,
        party_id,
        all_subsets_parties.clone()
    );

    let ecdsa = EcdsaLocalKeyData {
        local_key: ecdsa_local_key,
        offline_data: ecdsa_offline_data,
        algorithm: String::from("gg20"),
    };

    let eddsa_offline_data = presignature::generate_dynamic_nonces(
        request_id,
        token,
        &rust_address,
        &rust_room,
        0,
        max_nonce_per_refresh,
        &eddsa_local_key,
    )
    .await?;

    return Ok(KeygenResult {
        party_id,
        ecdsa,
        eddsa: EddsaLocalKeyData {
            local_key: eddsa_local_key,
            offline_data: eddsa_offline_data,
            algorithm: String::from("t_ed25519"),
        },
        members,
    });
}

#[ignore]
#[cfg(test)]
mod test {
    use std::thread;

    use rand::Rng;

    use crate::{
        gg20::signing,
        t_ed25519::{self, presignature},
    };

    #[tokio::test]
    async fn e2e_3_parties() {
        let data_to_sign = "hello".as_bytes().to_vec();
        let id: u16 = rand::thread_rng().gen();
        let room_id = format!("{}_{}", "kg_e2e_bundle", id);
        let room_id = room_id.as_str();
        let address = "http://localhost:8000";
        let t = 1;
        let n = 3;
        let no_nonces = 10;
        let _signing_message = "hello".as_bytes().to_vec();
        let machine1 = async move {
            thread::sleep(std::time::Duration::from_secs(1));
            println!("started machine1");
            let keygen_future = crate::all_keygen::keygen_and_offline(
                "requestId",
                "user1",
                address,
                room_id,
                t,
                n,
                1,
                "A",
            )
            .await;
            let keygen_result = keygen_future.unwrap();
            println!(
                "machine1: keygen result {}",
                serde_json::to_string(&keygen_result).unwrap()
            );

            let eddsa_generated_nonce = presignature::generate_dynamic_nonces(
                "requestId",
                "user1",
                address,
                room_id,
                0,
                no_nonces,
                &keygen_result.eddsa.local_key,
            )
            .await;
            println!(
                "machine1: eddsa_generated_nonce count {}",
                eddsa_generated_nonce.unwrap().completed_offline.len()
            );
            keygen_result
        };
        let machine2 = async move {
            thread::sleep(std::time::Duration::from_secs(1));
            println!("started machine2");
            let keygen_future = crate::all_keygen::keygen_and_offline(
                "requestId",
                "user2",
                address,
                room_id,
                t,
                n,
                1,
                "B",
            )
            .await;
            let keygen_result = keygen_future.unwrap();
            println!(
                "machine2: keygen result {}",
                serde_json::to_string(&keygen_result).unwrap()
            );

            let eddsa_generated_nonce = presignature::generate_dynamic_nonces(
                "requestId",
                "user2",
                address,
                room_id,
                0,
                no_nonces,
                &keygen_result.eddsa.local_key,
            )
            .await;
            println!(
                "machine2: eddsa_generated_nonce count {}",
                eddsa_generated_nonce.unwrap().completed_offline.len()
            );
            keygen_result
        };
        let machine3 = async move {
            thread::sleep(std::time::Duration::from_secs(1));
            println!("started machine3");
            let keygen_future = crate::all_keygen::keygen_and_offline(
                "requestId",
                "user3",
                address,
                room_id,
                t,
                n,
                1,
                "C",
            )
            .await;
            let keygen_result = keygen_future.unwrap();
            println!(
                "machine3: keygen result {}",
                serde_json::to_string(&keygen_result).unwrap()
            );

            let eddsa_generated_nonce = presignature::generate_dynamic_nonces(
                "requestId",
                "user3",
                address,
                room_id,
                0,
                no_nonces,
                &keygen_result.eddsa.local_key,
            )
            .await;
            println!(
                "machine3: eddsa_generated_nonce count {}",
                eddsa_generated_nonce.unwrap().completed_offline.len()
            );
            keygen_result
        };
        let (keygen_result1, keygen_result2, _keygen_result3) =
            tokio::join!(machine1, machine2, machine3);

        let parties = vec![keygen_result1.party_id, keygen_result2.party_id];
        let mut state_ecdsa = crate::utils::common::SigningState {
            t,
            n,
            signing_parts: vec![],
            signature: None,
        };
        signing::sign(
            &mut state_ecdsa,
            &keygen_result1.ecdsa,
            data_to_sign.clone(),
            keygen_result1.party_id,
            parties.clone(),
        )
        .unwrap();
        signing::sign(
            &mut state_ecdsa,
            &keygen_result2.ecdsa,
            data_to_sign.clone(),
            keygen_result2.party_id,
            parties.clone(),
        )
        .unwrap();
        println!("signed ecdsa message: {:?}", state_ecdsa.signature);

        let mut state_eddsa = crate::utils::common::SigningState {
            t,
            n,
            signing_parts: vec![],
            signature: None,
        };
        t_ed25519::signing::sign(
            &mut state_eddsa,
            &keygen_result1.eddsa,
            data_to_sign.clone(),
            keygen_result1.party_id,
            0,
        )
        .unwrap();
        t_ed25519::signing::sign(
            &mut state_eddsa,
            &keygen_result2.eddsa,
            data_to_sign.clone(),
            keygen_result2.party_id,
            0,
        )
        .unwrap();
        println!("signed eddsa message: {:?}", state_eddsa.signature);
    }
}
