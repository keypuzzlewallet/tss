use std::mem::replace;
use std::time::Duration;

use crate::t_ed25519::ErrorType;
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

use crate::t_ed25519::keygen::private::InternalError;
use crate::t_ed25519::thresholdsig::{KeyGenBroadcastMessage1, Keys, Parameters, SharedKeys};
use crate::utils::sm_client::join_computation;

pub async fn start_keygen(
    request_id: &str,
    token: &str,
    address: &str,
    room: &str,
    t: u16,
    n: u16,
    party_id: u16,
) -> anyhow::Result<EddsaLocalKey> {
    let (_, incoming, outgoing) = join_computation(
        request_id,
        token,
        surf::Url::parse(address)?,
        &format!("{}-eddsa", room),
        (1..(n + 1)).collect(),
        Some(party_id),
        None,
    )
    .await
    .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = EddsaKeygen::new(party_id, t, n)?;
    let local_share = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    Ok(local_share)
}

pub struct EddsaKeygen {
    round: R,
    msgs1: Option<Store<BroadcastMsgs<EddsaKeyGenBroadcastForRound1>>>,
    msgs2: Option<Store<P2PMsgs<EddsaKeyGenBroadcastForRound2>>>,
    msgs_queue: Vec<Msg<EddsaProtocolMessage>>,
    party_i: u16,
    party_n: u16,
}
// Rounds

enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Final(EddsaLocalKey),
    Gone,
}

struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

pub struct Round1 {
    keypair: Keys,
    round_msg: EddsaKeyGenBroadcastForRound1,

    party_i: u16,
    t: u16,
    n: u16,
}

pub struct Round2 {
    round_msg: EddsaKeyGenBroadcastForRound2,
    agg_pubkey: Point<Ed25519>,
    pubkeys_list: Vec<Point<Ed25519>>,

    keypair: Keys,

    party_i: u16,
    t: u16,
    n: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EddsaLocalKey {
    pub combined_share: SharedKeys,
    pub vss_schemes: Vec<VerifiableSS<Ed25519>>,
    pub agg_pubkey: Point<Ed25519>,
    pub pubkeys_list: Vec<Point<Ed25519>>,

    pub keypair: Keys,

    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> std::result::Result<Round1, ProceedError>
    where
        O: Push<Msg<EddsaKeyGenBroadcastForRound1>>,
    {
        let keypair = Keys::phase1_create(self.party_i);
        let (first_msg, first_msg_blind) = keypair.phase1_broadcast();
        let public_key = keypair.clone().keypair.public_key;

        let round_msg = EddsaKeyGenBroadcastForRound1 {
            first_msg,
            first_msg_blind,
            public_key,
        };
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: round_msg.clone(),
        });
        Ok(Round1 {
            round_msg,
            keypair,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<EddsaKeyGenBroadcastForRound1>,
        mut output: O,
    ) -> std::result::Result<Round2, ProceedError>
    where
        O: Push<Msg<EddsaKeyGenBroadcastForRound2>>,
    {
        let round_msgs = input.into_vec_including_me(self.round_msg);
        let pubkeys_list: Vec<_> = round_msgs
            .clone()
            .into_iter()
            .map(|msg| msg.public_key)
            .collect();
        let first_msgs: Vec<_> = round_msgs
            .clone()
            .into_iter()
            .map(|msg| msg.first_msg)
            .collect();
        let first_msg_blinds: Vec<_> = round_msgs
            .into_iter()
            .map(|msg| msg.first_msg_blind)
            .collect();
        let agg_pubkey = {
            let first_key = pubkeys_list[0].clone();
            pubkeys_list[1..].iter().fold(first_key, |acc, p| acc + p)
        };
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let parties: Vec<_> = (1..(self.n + 1)).collect();
        let (vss_scheme, secret_share) = self
            .keypair
            .phase1_verify_com_phase2_distribute(
                &params,
                &first_msg_blinds,
                &pubkeys_list,
                &first_msgs,
                &parties,
            )
            .unwrap();

        let round_msg = EddsaKeyGenBroadcastForRound2 {
            vss_scheme: vss_scheme.clone(),
            own_share: secret_share[self.party_i as usize - 1].clone(),
        };
        for (i, share) in secret_share.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: EddsaKeyGenBroadcastForRound2 {
                    vss_scheme: vss_scheme.clone(),
                    own_share: share.clone(),
                },
            })
        }

        Ok(Round2 {
            round_msg,
            pubkeys_list,
            agg_pubkey,
            keypair: self.keypair,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<EddsaKeyGenBroadcastForRound1>> {
        BroadcastMsgsStore::new(i, n)
    }
}

impl Round2 {
    pub fn proceed(
        self,
        input: P2PMsgs<EddsaKeyGenBroadcastForRound2>,
    ) -> std::result::Result<EddsaLocalKey, ProceedError> {
        let params = Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let round_msgs = input.into_vec_including_me(self.round_msg.clone());
        let parties_shares = round_msgs
            .clone()
            .into_iter()
            .map(|msg| msg.own_share.clone())
            .collect::<Vec<_>>();
        let vss_schemes = round_msgs
            .into_iter()
            .map(|msg| msg.vss_scheme.clone())
            .collect::<Vec<_>>();
        let combined_share = self
            .keypair
            .phase2_verify_vss_construct_keypair(
                &params,
                &self.pubkeys_list,
                &parties_shares,
                &vss_schemes,
                self.party_i,
            )
            .unwrap();

        Ok(EddsaLocalKey {
            combined_share,
            vss_schemes,
            agg_pubkey: self.agg_pubkey,
            pubkeys_list: self.pubkeys_list,
            keypair: self.keypair,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<EddsaKeyGenBroadcastForRound2>> {
        P2PMsgsStore::new(i, n)
    }
}

impl EddsaKeygen {
    pub fn new(i: u16, t: u16, n: u16) -> Result<Self> {
        if n < 2 {
            return Err(Error::TooFewParties);
        }
        if t == 0 || t >= n {
            return Err(Error::InvalidThreshold);
        }
        if i == 0 || i > n {
            return Err(Error::InvalidPartyIndex);
        }
        let mut state = Self {
            round: R::Round0(Round0 { party_i: i, t, n }),

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
    Round1(EddsaKeyGenBroadcastForRound1),
    Round2(EddsaKeyGenBroadcastForRound2),
}

impl StateMachine for EddsaKeygen {
    type MessageBody = EddsaProtocolMessage;
    type Err = Error;
    type Output = EddsaLocalKey;

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
    #[error("at least 2 parties are required for keygen")]
    TooFewParties,
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
pub struct EddsaKeyGenBroadcastForRound1 {
    pub first_msg: KeyGenBroadcastMessage1,
    pub first_msg_blind: BigInt,
    pub public_key: Point<Ed25519>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EddsaKeyGenBroadcastForRound2 {
    pub own_share: Scalar<Ed25519>,
    pub vss_scheme: VerifiableSS<Ed25519>,
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Self::InternalError(err)
    }
}
