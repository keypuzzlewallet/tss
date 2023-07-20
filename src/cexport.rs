use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use allo_isolate::Isolate;
use rustmodel::{
    KeyScheme, NativeGenerateDynamicNonceRequest, NativeKeygenRequest, NativeSigningRequest,
};

use crate::gg20;
use crate::t_ed25519;
use crate::t_ed25519::presignature::generate_dynamic_nonces;
use crate::utils::common::{
    decrypt_ecdsa, decrypt_eddsa, encrypt_eddsa_keygen_result, encrypt_keygen_result,
    signing_state_base64_to_obj, signing_state_obj_to_base64,
};

#[no_mangle]
pub extern "C" fn c_sign(c_request: *const c_char) -> *mut c_char {
    let rust_request = unsafe { CStr::from_ptr(c_request) }
        .to_str()
        .unwrap()
        .to_string();
    let request: NativeSigningRequest = match serde_json::from_str(rust_request.as_str()) {
        Ok(r) => r,
        Err(e) => {
            return CString::new(format!("error: {}", e.to_string()))
                .unwrap()
                .into_raw();
        }
    };
    let mut state = signing_state_base64_to_obj(&request.state_base64);
    let data = match hex::decode(request.hex_data) {
        Ok(r) => r,
        Err(e) => {
            return CString::new(format!("error: {}", e.to_string()))
                .unwrap()
                .into_raw();
        }
    };
    return match if request.key_scheme == KeyScheme::ECDSA {
        gg20::signing::sign(
            &mut state,
            &(match decrypt_ecdsa(&request.encrypted_local_key, request.password.as_str()) {
                Ok(r) => r,
                Err(e) => {
                    return CString::new(format!("error: {}", e.to_string()))
                        .unwrap()
                        .into_raw();
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
            &(match decrypt_eddsa(&request.encrypted_local_key, request.password.as_str()) {
                Ok(r) => r,
                Err(e) => {
                    return CString::new(format!("error: {}", e.to_string()))
                        .unwrap()
                        .into_raw();
                }
            }),
            data,
            request.party_id as u16,
            0,
        )
    } {
        Ok(()) => {
            let state_result_base64 = signing_state_obj_to_base64(request.key_scheme, &state);
            let state_result_base64_json = match serde_json::to_string(&state_result_base64) {
                Ok(state_result_base64_json) => state_result_base64_json,
                Err(e) => {
                    return CString::new(format!("error: {}", e.to_string()))
                        .unwrap()
                        .into_raw();
                }
            };
            CString::new(state_result_base64_json).unwrap().into_raw()
        }
        Err(e) => {
            return CString::new(format!("error: {}", e.to_string()))
                .unwrap()
                .into_raw();
        }
    };
}

#[no_mangle]
pub extern "C" fn c_keygen(c_request: *const c_char) {
    let rust_request = unsafe { CStr::from_ptr(c_request) }
        .to_str()
        .unwrap()
        .to_string();
    let request: NativeKeygenRequest = serde_json::from_str(rust_request.as_str()).unwrap();
    let isolate = Isolate::new(request.port);
    std::thread::spawn(move || {
        match tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(crate::all_keygen::keygen_and_offline(
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
                let encrypted_keygen_result =
                    encrypt_keygen_result(keygen_result, request.password.as_str());
                let encrypted_keygen_result_json =
                    match serde_json::to_string(&encrypted_keygen_result) {
                        Ok(r) => r,
                        Err(err) => {
                            isolate.post(format!("error: {}", err.to_string()));
                            return;
                        }
                    };
                isolate.post(encrypted_keygen_result_json);
            }
            Err(err) => {
                isolate.post(format!("error: {}", err.to_string()));
            }
        }
    });
}

#[no_mangle]
pub extern "C" fn c_generate_nonce(c_request: *const c_char) {
    let rust_request = unsafe { CStr::from_ptr(c_request) }
        .to_str()
        .unwrap()
        .to_string();
    let request: NativeGenerateDynamicNonceRequest =
        serde_json::from_str(rust_request.as_str()).unwrap();
    let isolate = Isolate::new(request.port);

    match decrypt_eddsa(&request.encrypted_local_key, request.password.as_str()) {
        Ok(local_key_data) => {
            std::thread::spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(generate_dynamic_nonces(
                        request.request_id.as_str(),
                        request.token.as_str(),
                        request.address.as_str(),
                        request.room.as_str(),
                        request.nonce_start_index as u16,
                        request.nonce_size as u16,
                        &local_key_data.local_key,
                    )) {
                    Ok(keygen_result) => {
                        let encrypted_keygen_result = encrypt_eddsa_keygen_result(
                            &local_key_data.local_key,
                            &keygen_result,
                            request.password.as_str(),
                            local_key_data.algorithm.as_str(),
                        );
                        let encrypted_keygen_result_json =
                            match serde_json::to_string(&encrypted_keygen_result) {
                                Ok(r) => r,
                                Err(err) => {
                                    isolate.post(format!("error: {}", err.to_string()));
                                    return;
                                }
                            };
                        isolate.post(encrypted_keygen_result_json);
                    }
                    Err(err) => {
                        isolate.post(format!("error: {}", err.to_string()));
                    }
                }
            });
        }
        Err(e) => {
            isolate.post(
                CString::new(format!("error: {}", e.to_string()))
                    .unwrap()
                    .into_raw(),
            );
        }
    };
}

#[cfg(test)]
mod test {
    use std::ffi::CString;

    use rand::Rng;
    use rustmodel::NativeKeygenRequest;

    #[test]
    fn e2e() {
        let id: u16 = rand::thread_rng().gen();
        let room_id = format!("{}_{}", "kg_e2e_c", id).to_owned();
        crate::cexport::c_keygen(
            CString::new(
                serde_json::to_string(&NativeKeygenRequest {
                    request_id: String::from("requestId"),
                    token: String::from("user1"),
                    t: 1,
                    n: 3,
                    address: "http://localhost:8000".to_owned(),
                    room: room_id.clone(),
                    signer_name: "A".to_owned(),
                    port: 8888,
                    password: String::from("123"),
                })
                .unwrap(),
            )
            .unwrap()
            .into_raw(),
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
        crate::cexport::c_keygen(
            CString::new(
                serde_json::to_string(&NativeKeygenRequest {
                    request_id: String::from("requestId"),
                    token: String::from("user2"),
                    t: 1,
                    n: 3,
                    address: "http://localhost:8000".to_owned(),
                    room: room_id.clone(),
                    signer_name: "B".to_owned(),
                    port: 8888,
                    password: String::from("123"),
                })
                .unwrap(),
            )
            .unwrap()
            .into_raw(),
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
        crate::cexport::c_keygen(
            CString::new(
                serde_json::to_string(&NativeKeygenRequest {
                    request_id: String::from("requestId"),
                    token: String::from("user3"),
                    t: 1,
                    n: 3,
                    address: "http://localhost:8000".to_owned(),
                    room: room_id.clone(),
                    signer_name: "C".to_owned(),
                    port: 8888,
                    password: String::from("123"),
                })
                .unwrap(),
            )
            .unwrap()
            .into_raw(),
        );
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
