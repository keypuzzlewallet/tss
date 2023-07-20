#![allow(dead_code)]

use anyhow::Context;
use base64::engine::general_purpose;
use base64::Engine;
use curv::{arithmetic::traits::Converter, elliptic::curves::secp256_k1::Secp256k1};
use futures::TryStreamExt;
use rustmodel::{
    EncryptedKeygenResult, EncryptedKeygenWithScheme, EncryptedLocalKey, KeyScheme, KeygenMember,
    KeygenProgress, SignatureRecidHex, SignedPartialSignatureBase64, SigningStateBase64,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::gg20::state_machine::keygen::LocalKey;
use crate::gg20::state_machine::sign;
use crate::gg20::state_machine::sign::{CompletedOfflineStage, PartialSignature};
use crate::t_ed25519::keygen::EddsaLocalKey;
use crate::t_ed25519::presignature::EddsaOffline;
use crate::t_ed25519::thresholdsig::LocalSig;
use crate::utils::encryption::{decrypt, encrypt};

pub type Key = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningState {
    pub t: u16,
    pub n: u16,
    pub signing_parts: Vec<SignedPartialSignature>,
    pub signature: Option<SignatureRecidHex>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPartialSignature {
    pub party_id: u16,
    pub part: PartialSignatureType,
    pub signed_at: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum PartialSignatureType {
    ECDSA(PartialSignature),
    EDDSA(LocalSig),
}

#[derive(Serialize, Deserialize)]
pub struct EcdsaLocalKeyData {
    pub local_key: LocalKey<Secp256k1>,
    pub offline_data: Vec<EcdsaOfflineResult>,
    pub algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct EddsaLocalKeyData {
    pub local_key: EddsaLocalKey,
    pub offline_data: EddsaOfflineResult,
    pub algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeygenResult {
    pub party_id: u16,
    pub ecdsa: EcdsaLocalKeyData,
    pub eddsa: EddsaLocalKeyData,
    pub members: Vec<KeygenMember>,
}

pub fn encrypt_keygen_result(result: KeygenResult, password: &str) -> EncryptedKeygenResult {
    return EncryptedKeygenResult {
        party_id: result.party_id as i32,
        encrypted_keygen_with_scheme: vec![
            encrypt_ecdsa_keygen_result(&result, password, result.ecdsa.algorithm.as_str()),
            encrypt_eddsa_keygen_result(
                &result.eddsa.local_key,
                &result.eddsa.offline_data,
                password,
                result.eddsa.algorithm.as_str(),
            ),
        ],
        members: result.members,
    };
}

pub fn encrypt_eddsa_keygen_result(
    local_key: &EddsaLocalKey,
    offline_data: &EddsaOfflineResult,
    password: &str,
    algorithm: &str,
) -> EncryptedKeygenWithScheme {
    EncryptedKeygenWithScheme {
        key_scheme: KeyScheme::EDDSA,
        nonce_start_index: offline_data.nonce_start_index as i32,
        nonce_size: offline_data.nonce_size as i32,
        encrypted_local_key: EncryptedLocalKey {
            algorithm: algorithm.to_string(),
            pubkey: hex::encode(&local_key.agg_pubkey.to_bytes(true).to_vec()),
            encrypted_key: encrypt(
                serde_json::to_string(&local_key).unwrap().as_str(),
                password,
            )
            .unwrap(),
            encrypted_nonce: encrypt(
                serde_json::to_string(&offline_data).unwrap().as_str(),
                password,
            )
            .unwrap(),
        },
    }
}

fn encrypt_ecdsa_keygen_result(
    result: &KeygenResult,
    password: &str,
    algorithm: &str,
) -> EncryptedKeygenWithScheme {
    EncryptedKeygenWithScheme {
        key_scheme: KeyScheme::ECDSA,
        nonce_start_index: 0,
        nonce_size: 1,
        encrypted_local_key: EncryptedLocalKey {
            pubkey: hex::encode(&result.ecdsa.local_key.public_key().to_bytes(true).to_vec()),
            algorithm: algorithm.to_string(),
            encrypted_key: encrypt(
                serde_json::to_string(&result.ecdsa.local_key)
                    .unwrap()
                    .as_str(),
                password,
            )
            .unwrap(),
            encrypted_nonce: encrypt(
                serde_json::to_string(&result.ecdsa.offline_data)
                    .unwrap()
                    .as_str(),
                password,
            )
            .unwrap(),
        },
    }
}

pub fn signing_state_obj_to_base64(scheme: KeyScheme, result: &SigningState) -> SigningStateBase64 {
    return SigningStateBase64 {
        t: result.t as i32,
        n: result.n as i32,
        key_scheme: scheme,
        signature: result.signature.clone(),
        signing_parts_base64: result
            .signing_parts
            .iter()
            .map(|x| SignedPartialSignatureBase64 {
                party_id: x.party_id.clone() as i32,
                part_base64: general_purpose::STANDARD
                    .encode(serde_json::to_string(&x.part.clone()).unwrap()),
                signed_at: x.signed_at.clone(),
            })
            .collect(),
    };
}

pub fn signing_state_base64_to_obj(result: &SigningStateBase64) -> SigningState {
    return SigningState {
        t: result.t as u16,
        n: result.n as u16,
        signature: result.signature.clone(),
        signing_parts: result
            .signing_parts_base64
            .iter()
            .map(|x| SignedPartialSignature {
                party_id: x.party_id.clone() as u16,
                part: if result.key_scheme == KeyScheme::ECDSA {
                    let r: sign::PartialSignature = serde_json::from_slice(
                        general_purpose::STANDARD
                            .decode(&x.part_base64)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
                    PartialSignatureType::ECDSA(r)
                } else {
                    let r: LocalSig = serde_json::from_slice::<LocalSig>(
                        general_purpose::STANDARD
                            .decode(&x.part_base64)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
                    PartialSignatureType::EDDSA(r)
                },
                signed_at: x.signed_at.clone(),
            })
            .collect(),
    };
}

#[derive(Serialize, Deserialize)]
pub struct EcdsaOfflineResult {
    pub parties: Vec<u16>,
    pub completed_offline: CompletedOfflineStage,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EddsaOfflineResult {
    pub parties: Vec<u16>,
    pub nonce_start_index: u16,
    pub nonce_size: u16,
    pub completed_offline: Vec<EddsaOffline>,
}

#[derive(Serialize, Deserialize)]
pub struct IssueIndexMsg {
    pub parties: Vec<u16>,
    pub party_id: Option<u16>,
    pub party_name: Option<String>,
}

pub fn powerset<T>(s: &[T]) -> Vec<Vec<T>>
where
    T: Clone,
{
    // The number of subsets is 2 raised to the power of the length of the slice
    let n = 2usize.pow(s.len() as u32);
    // A vector to store the subsets
    let mut result = Vec::with_capacity(n);
    // Loop through all possible bit masks from 0 to n - 1
    for i in 0..n {
        // A vector to store the current subset
        let mut subset = Vec::new();
        // Loop through each element in the slice and check if its corresponding bit is set in the mask
        for (j, element) in s.iter().enumerate() {
            if (i >> j) & 1 == 1 {
                // If yes, add it to the subset
                subset.push(element.clone());
            }
        }
        // Add the subset to the result
        result.push(subset);
    }
    // Return the result
    result
}

pub fn decrypt_ecdsa(
    local_key: &EncryptedLocalKey,
    password: &str,
) -> anyhow::Result<EcdsaLocalKeyData> {
    Ok(EcdsaLocalKeyData {
        algorithm: local_key.algorithm.clone(),
        local_key: serde_json::from_str(
            decrypt(local_key.encrypted_key.as_str(), password)
                .context("failed decrypt ECDSA localKey")?
                .as_str(),
        )?,
        offline_data: serde_json::from_str(
            decrypt(local_key.encrypted_nonce.as_str(), password)
                .context("failed decrypt ECDSA Nonce")?
                .as_str(),
        )?,
    })
}

pub fn decrypt_eddsa(
    local_key: &EncryptedLocalKey,
    password: &str,
) -> anyhow::Result<EddsaLocalKeyData> {
    Ok(EddsaLocalKeyData {
        algorithm: local_key.algorithm.clone(),
        local_key: serde_json::from_str(
            decrypt(local_key.encrypted_key.as_str(), password)
                .context("failed decrypt EDDSA localKey")?
                .as_str(),
        )?,
        offline_data: serde_json::from_str(
            decrypt(local_key.encrypted_nonce.as_str(), password)
                .context("failed decrypt EDDSA Nonce")?
                .as_str(),
        )?,
    })
}

pub async fn get_progress(
    request_id: &str,
    token: &str,
    address: surf::Url,
    room_id: &str,
) -> KeygenProgress {
    let http_client: surf::Client = surf::Config::new()
        .set_base_url(address.join(&format!("rooms/{}/", room_id)).unwrap())
        .set_timeout(None)
        .try_into()
        .unwrap();
    return http_client
        .get("status")
        .header("X-Request-ID", request_id)
        .header("X-Token", token)
        .recv_json::<KeygenProgress>()
        .await
        .map_err(|e| e.into_inner())
        .unwrap();
}

#[cfg(test)]
mod test {
    use crate::utils::common::powerset;

    #[test]
    fn test_powerset() {
        let tt = powerset(vec![3, 1, 2].as_slice());
        let mut t: Vec<_> = tt.iter().filter(|&x| x.len() == 2).collect();
        t.sort();
        println!("{:?}", t);
    }
}
