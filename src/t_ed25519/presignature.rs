use std::time::Duration;
use std::{collections::HashMap, mem::replace};

use anyhow::{anyhow, Context};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use curv::BigInt;
use futures::StreamExt;
use round_based::containers::{
    push::{Push, PushExt},
    *,
};
use round_based::{AsyncProtocol, IsCritical, Msg, StateMachine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::t_ed25519::keygen::EddsaLocalKey;
use crate::t_ed25519::presignature::private::InternalError;
use crate::t_ed25519::thresholdsig::{
    EphemeralKey, EphemeralSharedKeys, KeyGenBroadcastMessage1, Keys, Parameters,
};
use crate::t_ed25519::ErrorType;
use crate::utils::common::EddsaOfflineResult;
use crate::utils::sm_client::join_computation;

pub async fn generate_offline_signing(
    request_id: &str,
    token: &str,
    local_share: &Keys,
    address: &str,
    room: &str,
    t: u16,
    n: u16,
    party_id: u16,
    parties: Vec<u16>,
    no_nonces: u16,
) -> anyhow::Result<Vec<EddsaOffline>> {
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

    let signing = EddsaOfflineGen::new(
        local_share,
        party_id,
        t,
        parties.clone(),
        n,
        no_nonces,
        request_id,
    )?;
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

pub async fn generate_dynamic_nonces(
    request_id: &str,
    token: &str,
    rust_address: &str,
    rust_room: &str,
    nonce_start_index: u16,
    max_nonce_per_refresh: u16,
    eddsa_local_key: &EddsaLocalKey,
) -> anyhow::Result<EddsaOfflineResult> {
    let all_parties: Vec<u16> = (1..(eddsa_local_key.n + 1)).collect();
    let completed_offline = crate::t_ed25519::presignature::generate_offline_signing(
        request_id,
        token,
        &eddsa_local_key.clone().keypair,
        rust_address,
        format!(
            "{}-eddsa-offline-{}_{}",
            rust_room, nonce_start_index, max_nonce_per_refresh
        )
        .as_str(),
        eddsa_local_key.t,
        eddsa_local_key.n,
        eddsa_local_key.party_i,
        all_parties.clone(),
        max_nonce_per_refresh,
    )
    .await?;
    let eddsa_offline_data = EddsaOfflineResult {
        parties: all_parties.clone(),
        nonce_start_index,
        nonce_size: nonce_start_index + max_nonce_per_refresh,
        completed_offline,
    };
    Ok(eddsa_offline_data)
}

pub struct EddsaOfflineGen {
    round: R,
    msgs1: Option<Store<BroadcastMsgs<Vec<EddsaOfflineBroadcastForRound1>>>>,
    msgs2: Option<Store<P2PMsgs<Vec<EddsaOfflineBroadcastForRound2>>>>,
    msgs_queue: Vec<Msg<EddsaProtocolMessage>>,
    party_i: u16,
    party_n: u16,
}
// Rounds

enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Final(Vec<EddsaOffline>),
    Gone,
}

struct Round0 {
    pub keypair: Keys,
    pub party_i: u16,
    pub t: u16,
    pub parties: Vec<u16>,
    pub n: u16,
    pub no_nonces: u16,
    pub request_id: String,
}

pub struct Round1 {
    round_msg: Vec<EddsaOfflineBroadcastForRound1>,
    nonce_key: Vec<EphemeralKey>,

    keypair: Keys,
    party_i: u16,
    t: u16,
    parties: Vec<u16>,
    n: u16,
    no_nonces: u16,
    request_id: String,
}

pub struct Round2 {
    round_msg: Vec<EddsaOfflineBroadcastForRound2>,
    agg_nonce: Vec<Point<Ed25519>>,
    Rs: Vec<Vec<Point<Ed25519>>>,

    nonce_key: Vec<EphemeralKey>,
    keypair: Keys,

    party_i: u16,
    t: u16,
    parties: Vec<u16>,
    n: u16,
    no_nonces: u16,
    request_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EddsaOffline {
    pub nonce_vss_schemes: Vec<VerifiableSS<Ed25519>>,
    pub combined_nonce_share: EphemeralSharedKeys,
    pub agg_nonce: Point<Ed25519>,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> std::result::Result<Round1, ProceedError>
    where
        O: Push<Msg<Vec<EddsaOfflineBroadcastForRound1>>>,
    {
        let mut round_msg = vec![];
        let mut nonce_key = vec![];

        for _ in 0..self.no_nonces {
            let ephemeral_key = EphemeralKey::ephermeral_key_create_from_deterministic_secret(
                &self.keypair,
                &[],
                self.party_i,
            );
            let (R, nonce_key_i) = (ephemeral_key.R_i.clone(), ephemeral_key);
            let (first_msg, first_msg_blind) = nonce_key_i.phase1_broadcast();
            nonce_key.push(nonce_key_i);

            round_msg.push(EddsaOfflineBroadcastForRound1 {
                first_msg,
                first_msg_blind,
                R,
            });
            println!(
                "requestId={} round 0: party {} broadcasted nonce key",
                self.request_id, self.party_i
            );
        }
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: round_msg.clone(),
        });
        Ok(Round1 {
            round_msg,
            nonce_key,
            keypair: self.keypair,
            party_i: self.party_i,
            t: self.t,
            parties: self.parties,
            n: self.n,
            no_nonces: self.no_nonces,
            request_id: self.request_id,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<Vec<EddsaOfflineBroadcastForRound1>>,
        mut output: O,
    ) -> std::result::Result<Round2, ProceedError>
    where
        O: Push<Msg<Vec<EddsaOfflineBroadcastForRound2>>>,
    {
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let round_msgs = input.into_vec_including_me(self.round_msg.clone());
        let mut Rs = vec![];
        let mut round_msg = vec![];
        let mut agg_nonce = vec![];
        let mut nonce_secret_share = vec![];
        let mut nonce_vss_scheme = vec![];
        for i in 0..self.no_nonces as usize {
            let Rs_i: Vec<_> = round_msgs
                .clone()
                .into_iter()
                .map(|m| m[i].clone().R)
                .collect();
            Rs.push(Rs_i.clone());
            let first_msgs: Vec<_> = round_msgs
                .clone()
                .into_iter()
                .map(|m| m[i].clone().first_msg)
                .collect();
            let first_msg_blinds: Vec<_> = round_msgs
                .clone()
                .into_iter()
                .map(|m| m[i].clone().first_msg_blind)
                .collect();
            agg_nonce.push({
                let first_key = Rs_i[0].clone();
                Rs_i[1..].iter().fold(first_key, |acc, p| acc + p)
            });
            let (nonce_vss_scheme_i, nonce_secret_share_i) = self.nonce_key[i]
                .phase1_verify_com_phase2_distribute(
                    &params,
                    &first_msg_blinds,
                    &Rs_i,
                    &first_msgs,
                    &self.parties,
                )
                .unwrap();

            round_msg.push(EddsaOfflineBroadcastForRound2 {
                nonce_vss_scheme: nonce_vss_scheme_i.clone(),
                nonce_own_share: nonce_secret_share_i[self.party_i as usize - 1].clone(),
            });
            nonce_secret_share.push(nonce_secret_share_i);
            nonce_vss_scheme.push(nonce_vss_scheme_i);
            println!(
                "requestId={} round 1: party {} broadcasted nonce secret share",
                self.request_id, self.party_i
            );
        }
        let mut output_msg = HashMap::new();
        for x in 0..self.no_nonces as usize {
            for (i, share) in nonce_secret_share[x].iter().enumerate() {
                if i + 1 == usize::from(self.party_i) {
                    continue;
                }
                output_msg.entry(i + 1).or_insert_with(Vec::new).push(
                    EddsaOfflineBroadcastForRound2 {
                        nonce_vss_scheme: nonce_vss_scheme[x].clone(),
                        nonce_own_share: share.clone(),
                    },
                );
            }
        }

        output_msg.keys().for_each(|i| {
            output.push(Msg {
                sender: self.party_i,
                receiver: Some((*i) as u16),
                body: output_msg[i].clone(),
            })
        });

        Ok(Round2 {
            round_msg,
            agg_nonce,
            Rs,

            nonce_key: self.nonce_key,
            keypair: self.keypair,
            party_i: self.party_i,
            t: self.t,
            parties: self.parties,
            n: self.n,
            no_nonces: self.no_nonces,
            request_id: self.request_id,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<Vec<EddsaOfflineBroadcastForRound1>>> {
        BroadcastMsgsStore::new(i, n)
    }
}

impl Round2 {
    pub fn proceed(
        self,
        input: P2PMsgs<Vec<EddsaOfflineBroadcastForRound2>>,
    ) -> std::result::Result<Vec<EddsaOffline>, ProceedError> {
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let round_msgs = input.into_vec_including_me(self.round_msg.clone());
        let mut result = vec![];
        for i in 0..self.no_nonces as usize {
            let nonce_parties_share: Vec<_> = round_msgs
                .clone()
                .into_iter()
                .map(|m| m[i].clone().nonce_own_share)
                .collect();
            let nonce_vss_schemes: Vec<_> = round_msgs
                .clone()
                .into_iter()
                .map(|m| m[i].clone().nonce_vss_scheme)
                .collect();
            let combined_nonce_share = self.nonce_key[i]
                .phase2_verify_vss_construct_keypair(
                    &params,
                    &self.Rs[i],
                    &nonce_parties_share,
                    &nonce_vss_schemes,
                    self.party_i,
                )
                .unwrap();
            result.push(EddsaOffline {
                combined_nonce_share,
                nonce_vss_schemes,
                agg_nonce: self.agg_nonce[i].clone(),
            });
            println!(
                "requestId={} round 2: party {} broadcasted nonce vss scheme",
                self.request_id, self.party_i
            );
        }

        Ok(result)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<Vec<EddsaOfflineBroadcastForRound2>>> {
        P2PMsgsStore::new(i, n)
    }
}

impl EddsaOfflineGen {
    pub fn new(
        keypair: &Keys,
        i: u16,
        t: u16,
        parties: Vec<u16>,
        n: u16,
        no_nonces: u16,
        request_id: &str,
    ) -> Result<Self> {
        if n < 2 {
            return Err(Error::TooFewParties);
        }
        if no_nonces < 1 {
            return Err(Error::TooFewNonces);
        }
        if t == 0 || t >= n {
            return Err(Error::InvalidThreshold);
        }
        if i == 0 || i > n {
            return Err(Error::InvalidPartyIndex);
        }
        let mut state = Self {
            round: R::Round0(Round0 {
                party_i: i,
                keypair: keypair.clone(),
                t,
                parties,
                n,
                no_nonces,
                request_id: request_id.to_string(),
            }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),

            msgs_queue: vec![],
            party_i: i,
            party_n: n,
        };

        state.proceed_round(false)?;
        Ok(state)
    }

    fn gmap_queue<'a, T, F>(&'a mut self, mut f: F) -> impl Push<Msg<T>> + 'a
    where
        F: FnMut(T) -> M + 'a,
    {
        (&mut self.msgs_queue).gmap(move |m: Msg<T>| m.map_body(|m| EddsaProtocolMessage(f(m))))
    }

    /// Proceeds round state if it received enough messages and if it's cheap to compute or
    /// `may_block == true`
    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: R;
        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(self.gmap_queue(M::Round1))
                    .map(R::Round1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round2))
                    .map(R::Round2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs)
                    .map(R::Final)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
            s @ R::Final(_) | s @ R::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EddsaProtocolMessage(M);

#[derive(Clone, Debug, Serialize, Deserialize)]
enum M {
    Round1(Vec<EddsaOfflineBroadcastForRound1>),
    Round2(Vec<EddsaOfflineBroadcastForRound2>),
}

impl StateMachine for EddsaOfflineGen {
    type MessageBody = EddsaProtocolMessage;
    type Err = Error;
    type Output = Vec<EddsaOffline>;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
        let current_round = self.current_round();

        match msg.body {
            EddsaProtocolMessage(M::Round1(m)) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
            EddsaProtocolMessage(M::Round2(m)) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
            R::Round2(_) => !store2_wants_more,
            R::Final(_) | R::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<()> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, R::Final(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output>> {
        match self.round {
            R::Final(_) => (),
            R::Gone => return Some(Err(Error::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, R::Gone) {
            R::Final(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            R::Round0(_) => 0,
            R::Round1(_) => 1,
            R::Round2(_) => 2,
            R::Final(_) | R::Gone => 3,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(2)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

mod private {
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum InternalError {
        /// [Messages store](super::MessageStore) reported that it received all messages it wanted to receive,
        /// but refused to return message container
        RetrieveRoundMessages(super::StoreErr),
        #[doc(hidden)]
        StoreGone,
    }
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        true
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Round proceeding resulted in error
    #[error("proceed round: {0}")]
    ProceedRound(#[source] ProceedError),
    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for offline")]
    TooFewParties,
    #[error("at least 2 nonces are required for offline")]
    TooFewNonces,
    /// Threshold value `t` is not in range `[1; n-1]`
    #[error("threshold is not in range [1; n-1]")]
    InvalidThreshold,
    #[error("pick_output called twice")]
    DoublePickOutput,
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,
    #[doc(hidden)]
    #[error("internal error: {0:?}")]
    InternalError(InternalError),
    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },

    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),
}

#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 1: Rng: {0:?}")]
    Round1Error(ErrorType),
    #[error("round 2: Nonces: {0:?}")]
    Round2Error(ErrorType),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EddsaOfflineBroadcastForRound1 {
    pub first_msg: KeyGenBroadcastMessage1,
    pub first_msg_blind: BigInt,
    pub R: Point<Ed25519>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EddsaOfflineBroadcastForRound2 {
    pub nonce_vss_scheme: VerifiableSS<Ed25519>,
    pub nonce_own_share: Scalar<Ed25519>,
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Self::InternalError(err)
    }
}
