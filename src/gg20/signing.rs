use std::collections::HashSet;

use anyhow::Result;
use anyhow::{anyhow, Context};
use chrono::prelude::*;
use curv::arithmetic::Converter;
use curv::BigInt;
use rustmodel::SignatureRecidHex;

use crate::gg20::party_i;
use crate::gg20::state_machine::sign::{PartialSignature, SignManual};
use crate::utils::common::{
    EcdsaLocalKeyData, PartialSignatureType, SignedPartialSignature, SigningState,
};

pub fn sign(
    state: &mut SigningState,
    local_key: &EcdsaLocalKeyData,
    data_to_sign: Vec<u8>,
    party_id: u16,
    signers: Vec<u16>,
) -> Result<()> {
    if state.signing_parts.len() as u16 > state.t as u16 {
        // this already full signed
        Err(anyhow!("already signed"))
    } else {
        let signers_set: HashSet<u16> = signers.into_iter().collect();
        let completed_offline_stage = local_key
            .offline_data
            .iter()
            .find(|x| signers_set.eq(&x.parties.clone().into_iter().collect()))
            .unwrap()
            .completed_offline
            .clone();
        let msg = BigInt::from_bytes(&data_to_sign);
        let (signing, partial_signature) =
            SignManual::new(msg.clone(), completed_offline_stage.clone())?;
        if state.signing_parts.len() as u16 > state.t as u16 - 1 {
            let parts: Vec<SignedPartialSignature> = state.signing_parts.clone();
            let gt: Vec<PartialSignature> = parts
                .into_iter()
                .map(|x| match x.part {
                    PartialSignatureType::ECDSA(p) => p,
                    _ => panic!("wrong signature type"),
                })
                .collect();
            let signature = signing.complete(&gt).context("online stage failed")?;
            state.signing_parts.push(SignedPartialSignature {
                party_id,
                part: PartialSignatureType::ECDSA(partial_signature),
                signed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });
            state.signature = Some(SignatureRecidHex {
                r: hex::encode(&signature.r.to_bytes().to_vec()),
                s: hex::encode(&signature.s.to_bytes().to_vec()),
                recid: signature.recid as i32,
            });
            match party_i::verify(&signature, completed_offline_stage.public_key(), &msg) {
                Ok(_) => (),
                Err(_) => {
                    return Err(anyhow!("signature verification failed"));
                }
            }
        } else {
            state.signing_parts.push(SignedPartialSignature {
                party_id,
                part: PartialSignatureType::ECDSA(partial_signature),
                signed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::gg20::signing::sign;
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
            hex::encode(&shard1.ecdsa.local_key.public_key().to_bytes(true).to_vec()),
            "02c090469fbb29bed9419ace8d4acc50abbc39dedd00b0e3fa861f817fae78d873"
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
        sign(
            &mut state,
            &shard1.ecdsa,
            message_to_sign.clone(),
            1,
            vec![1, 2],
        )
        .unwrap();
        sign(
            &mut state,
            &shard2.ecdsa,
            message_to_sign.clone(),
            2,
            vec![1, 2],
        )
        .unwrap();
        assert_eq!(
            state.signature.clone().unwrap().r,
            "ca94ea1001fb90e4cce44d49bb9da0716091cf38caa5b7f03b3c838f59146829"
        );
        assert_eq!(
            state.signature.clone().unwrap().s,
            "0fa207ee408439a2ff8687696cf6bc4ac89035d09bab50b695c47f258e4859c3"
        );
        assert_eq!(state.signature.unwrap().recid, 0);
    }
}
