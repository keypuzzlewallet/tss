use anyhow::Result;
use anyhow::{anyhow, Context};
use chrono::prelude::*;
use curv::arithmetic::Converter;

use crate::t_ed25519::thresholdsig;
use crate::t_ed25519::thresholdsig::LocalSig;
use rustmodel::SignatureRecidHex;

use crate::utils::common::{
    EddsaLocalKeyData, PartialSignatureType, SignedPartialSignature, SigningState,
};

pub fn sign(
    state: &mut SigningState,
    local_key: &EddsaLocalKeyData,
    data_to_sign: Vec<u8>,
    party_id: u16,
    nonce: usize,
) -> Result<()> {
    if state.signing_parts.len() as u16 > state.t {
        // this already full signed
        Err(anyhow!("already signed"))
    } else {
        let nonce_index = nonce - local_key.offline_data.nonce_start_index as usize;
        if nonce_index < 0 || nonce_index >= local_key.offline_data.completed_offline.len() {
            return Err(anyhow!(
                "nonce index {} out of range [{},{}]",
                nonce_index,
                local_key.offline_data.nonce_start_index,
                local_key.offline_data.completed_offline.len()
                    + local_key.offline_data.nonce_start_index as usize
            ));
        }
        let partial_signature = LocalSig::compute(
            &data_to_sign,
            &local_key.offline_data.completed_offline[nonce_index].combined_nonce_share,
            &local_key.local_key.combined_share,
        );
        if state.signing_parts.len() as u16 > state.t as u16 - 1 {
            // the last part signed. now combine into one signature
            state.signing_parts.push(SignedPartialSignature {
                party_id,
                part: PartialSignatureType::EDDSA(partial_signature),
                signed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });

            let parts: Vec<_> = state.signing_parts.clone();
            let local_sig_vec: Vec<_> = parts
                .into_iter()
                .map(|x| match x.part {
                    PartialSignatureType::EDDSA(p) => p,
                    _ => panic!("wrong signature type"),
                })
                .collect();
            let verify_local_sig = LocalSig::verify_local_sigs(
                &local_sig_vec,
                &state
                    .signing_parts
                    .clone()
                    .iter()
                    .map(|x| x.party_id - 1)
                    .collect::<Vec<_>>(),
                &local_key.local_key.vss_schemes,
                &local_key.offline_data.completed_offline[nonce].nonce_vss_schemes,
            );
            let vss_sum_local_sigs = verify_local_sig.context("verify local sig failed")?;
            let signature = thresholdsig::generate(
                &vss_sum_local_sigs,
                &local_sig_vec,
                &state
                    .signing_parts
                    .clone()
                    .iter()
                    .map(|x| x.party_id - 1)
                    .collect::<Vec<_>>(),
                local_key.offline_data.completed_offline[nonce]
                    .clone()
                    .agg_nonce,
            );
            state.signature = Some(SignatureRecidHex {
                r: hex::encode(&signature.R.to_bytes(true).to_vec()),
                s: hex::encode(&signature.s.to_bytes().to_vec()),
                recid: 0,
            });
            match signature.verify(&data_to_sign, &local_key.local_key.agg_pubkey) {
                Ok(_) => (),
                Err(_) => {
                    return Err(anyhow!("signature verification failed"));
                }
            }
        } else {
            // not all parties signed. so push to the state for the next signer
            state.signing_parts.push(SignedPartialSignature {
                party_id,
                part: PartialSignatureType::EDDSA(partial_signature),
                signed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::t_ed25519::signing::sign;
    use crate::utils::common::{KeygenResult, SigningState};
    use crate::utils::test_wallets;

    #[test]
    fn should_sign_a_message() {
        let shard1: KeygenResult =
            serde_json::from_str(test_wallets::wallet1_shard1().as_str()).unwrap();
        let shard2: KeygenResult =
            serde_json::from_str(test_wallets::wallet1_shard2().as_str()).unwrap();
        let _shard3: KeygenResult =
            serde_json::from_str(test_wallets::wallet1_shard3().as_str()).unwrap();

        assert_eq!(
            hex::encode(&shard1.eddsa.local_key.agg_pubkey.to_bytes(true).to_vec()),
            "52d16db05136ddc0a64741a784a2d316b52f0ca3ba32ebcd1302d4c76ec4f4eb"
        );

        let mut state = SigningState {
            t: 1,
            n: 3,
            signing_parts: vec![],
            signature: None,
        };
        let message_to_sign =
            hex::decode("bd82be05afedc3f399efde5cda2e590c69b6478bf888dc38c961b12105485333")
                .unwrap();
        sign(&mut state, &shard1.eddsa, message_to_sign.clone(), 1, 0).unwrap();
        sign(&mut state, &shard2.eddsa, message_to_sign.clone(), 2, 0).unwrap();
        assert_eq!(
            state.signature.clone().unwrap().r,
            "c778b1d931d96ce8709876d4c06708bfe0b7dd567ad24105118bad17352e5a83"
        );
        assert_eq!(
            state.signature.clone().unwrap().s,
            "f859953107a36000cd4d6dee5dc478fe4ee9b157f0b44cd3b218b8fa3046f509"
        );
        assert_eq!(state.signature.unwrap().recid, 0);
    }
}
