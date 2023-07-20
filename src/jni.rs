use robusta_jni::bridge;

#[bridge]
pub mod jni {
    use std::convert::Infallible;

    use rustmodel::{
        KeyScheme, NativeGenerateDynamicNonceRequest, NativeKeygenRequest, NativeSigningRequest,
    };

    use crate::t_ed25519::presignature::generate_dynamic_nonces;
    use crate::utils::common::{
        decrypt_ecdsa, decrypt_eddsa, encrypt_eddsa_keygen_result, encrypt_keygen_result,
        signing_state_base64_to_obj, signing_state_obj_to_base64,
    };
    use crate::{gg20, t_ed25519};

    #[package(com.walletbackend.signingv2.jnitssv3)]
    pub struct JniTssv3();

    impl JniTssv3 {
        pub extern "jni" fn jniSign(
            rust_request: String,
        ) -> robusta_jni::jni::errors::Result<String> {
            let request: NativeSigningRequest = serde_json::from_str(rust_request.as_str())
                .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let data = hex::decode(request.hex_data)
                .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let mut state = signing_state_base64_to_obj(&request.state_base64);
            return match if request.key_scheme == KeyScheme::ECDSA {
                gg20::signing::sign(
                    &mut state,
                    &(match decrypt_ecdsa(&request.encrypted_local_key, request.password.as_str()) {
                        Ok(r) => r,
                        Err(e) => {
                            return Err(robusta_jni::jni::errors::Error::from(e.to_string()));
                        }
                    }),
                    data,
                    request.party_id as u16,
                    request
                        .signers
                        .into_iter()
                        .map(|x| x as u16)
                        .collect::<Vec<u16>>(),
                )
            } else {
                t_ed25519::signing::sign(
                    &mut state,
                    &decrypt_eddsa(&request.encrypted_local_key, request.password.as_str())
                        .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?,
                    data,
                    request.party_id as u16,
                    request.nonce as usize,
                )
            } {
                Ok(()) => {
                    let state_result_base64 = signing_state_obj_to_base64(KeyScheme::ECDSA, &state);
                    let state_result_base64_json = serde_json::to_string(&state_result_base64)
                        .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
                    Ok(state_result_base64_json)
                }
                Err(e) => Err(robusta_jni::jni::errors::Error::from(e.to_string())),
            };
        }
    }

    #[package(com.walletbackend.keygenv2.jnitssv3)]
    pub struct JniTssv3Keygen();

    impl JniTssv3Keygen {
        pub extern "jni" fn jniKeygen(
            rust_request: String,
        ) -> robusta_jni::jni::errors::Result<()> {
            let request: NativeKeygenRequest = serde_json::from_str(rust_request.as_str())
                .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let url =
                surf::Url::parse(format!("{}/rooms/{}/", request.address, request.room).as_str())
                    .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let http_client: surf::Client = surf::Config::new()
                .set_base_url(url)
                .set_timeout(None)
                .try_into()
                .map_err(|e: Infallible| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                match runtime.block_on(crate::all_keygen::keygen_and_offline(
                    request.request_id.as_str(),
                    request.token.as_str(),
                    request.address.as_str(),
                    request.room.as_str(),
                    request.t as u16,
                    request.n as u16,
                    crate::utils::constants::CONST_MAX_NONCE_PER_REFRESH,
                    request.signer_name.as_str(),
                )) {
                    Ok(keygen_result) => {
                        runtime.block_on(
                            std::thread::spawn(|| async move {
                                let keygen_result_base64 =
                                    encrypt_keygen_result(keygen_result, request.password.as_str());
                                let encrypted_result =
                                    match serde_json::to_string(&keygen_result_base64) {
                                        Ok(r) => r,
                                        Err(err) => {
                                            http_client
                                                .post("error")
                                                .header("X-Request-ID", request.request_id.clone())
                                                .header("X-Token", request.token.clone())
                                                .body(format!("error: {}", err.to_string()))
                                                .await;
                                            format!("error: {}", err.to_string())
                                        }
                                    };
                                http_client
                                    .post("completed-keygen")
                                    .header("X-Request-ID", request.request_id.clone())
                                    .header("X-Token", request.token.clone())
                                    .header("Content-Type", "application/json")
                                    .body(encrypted_result)
                                    .await;
                            })
                            .join()
                            .unwrap(),
                        );
                    }
                    Err(err) => {
                        runtime.block_on(
                            std::thread::spawn(|| async move {
                                http_client
                                    .post("error")
                                    .header("X-Request-ID", request.request_id)
                                    .header("X-Token", request.token.clone())
                                    .body(format!("error: {}", err.to_string()))
                                    .await;
                            })
                            .join()
                            .unwrap(),
                        );
                    }
                }
            });
            return Ok(());
        }

        pub extern "jni" fn jniGenerateNonce(
            rust_request: String,
        ) -> robusta_jni::jni::errors::Result<()> {
            let request: NativeGenerateDynamicNonceRequest =
                serde_json::from_str(rust_request.as_str())
                    .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let url =
                surf::Url::parse(format!("{}/rooms/{}/", request.address, request.room).as_str())
                    .map_err(|e| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let http_client: surf::Client = surf::Config::new()
                .set_base_url(url)
                .set_timeout(None)
                .try_into()
                .map_err(|e: Infallible| robusta_jni::jni::errors::Error::from(e.to_string()))?;
            let local_key_data =
                match decrypt_eddsa(&request.encrypted_local_key, request.password.as_str()) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(robusta_jni::jni::errors::Error::from(e.to_string()));
                    }
                };
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                match runtime.block_on(generate_dynamic_nonces(
                    request.request_id.as_str(),
                    request.token.as_str(),
                    request.address.as_str(),
                    request.room.as_str(),
                    request.nonce_start_index as u16,
                    request.nonce_size as u16,
                    &local_key_data.local_key,
                )) {
                    Ok(keygen_result) => {
                        runtime.block_on(
                            std::thread::spawn(|| async move {
                                let keygen_result_base64 = encrypt_eddsa_keygen_result(
                                    &local_key_data.local_key,
                                    &keygen_result,
                                    request.password.as_str(),
                                    local_key_data.algorithm.as_str(),
                                );
                                let encrypted_result =
                                    match serde_json::to_string(&keygen_result_base64) {
                                        Ok(r) => r,
                                        Err(err) => {
                                            http_client
                                                .post("error")
                                                .header("X-Request-ID", request.request_id.clone())
                                                .header("X-Token", request.token.clone())
                                                .body(format!("error: {}", err.to_string()))
                                                .await;
                                            format!("error: {}", err.to_string())
                                        }
                                    };
                                http_client
                                    .post("completed-generate-nonce")
                                    .header("X-Request-ID", request.request_id.clone())
                                    .header("X-Token", request.token.clone())
                                    .header("Content-Type", "application/json")
                                    .body(encrypted_result)
                                    .await;
                            })
                            .join()
                            .unwrap(),
                        );
                    }
                    Err(err) => {
                        runtime.block_on(
                            std::thread::spawn(|| async move {
                                http_client
                                    .post("error")
                                    .header("X-Request-ID", request.request_id)
                                    .header("X-Token", request.token.clone())
                                    .body(format!("error: {}", err.to_string()))
                                    .await;
                            })
                            .join()
                            .unwrap(),
                        );
                    }
                }
            });
            return Ok(());
        }
    }
}
