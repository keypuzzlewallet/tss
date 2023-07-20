use std::convert::TryInto;

use anyhow::{Context, Result};
use futures::{Sink, Stream, StreamExt, TryStreamExt};
use round_based::Msg;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use structopt::StructOpt;

use crate::utils::common::IssueIndexMsg;

pub async fn join_computation<M>(
    request_id: &str,
    token: &str,
    address: surf::Url,
    room_id: &str,
    parties: Vec<u16>,
    party_id: Option<u16>,
    party_name: Option<String>,
) -> Result<(
    u16,
    impl Stream<Item = Result<Msg<M>>>,
    impl Sink<Msg<M>, Error = anyhow::Error>,
)>
where
    M: Serialize + DeserializeOwned,
{
    let client =
        SmClient::new(request_id, token, address, room_id).context("construct SmClient")?;

    // Obtain party index
    let serialized = serde_json::to_string(&IssueIndexMsg {
        parties,
        party_id,
        party_name,
    })
    .context("serialize message")?;
    let index = client
        .issue_index(&serialized)
        .await
        .context("issue an index")?;

    // Construct channel of incoming messages
    let incoming = client
        .subscribe()
        .await
        .context("subscribe")?
        .and_then(|msg| async move {
            serde_json::from_str::<Msg<M>>(&msg).context("deserialize message")
        });

    // Ignore incoming messages addressed to someone else
    let incoming = incoming.try_filter(move |msg| {
        futures::future::ready(
            msg.sender != index && (msg.receiver.is_none() || msg.receiver == Some(index)),
        )
    });

    // Construct channel of outgoing messages
    let outgoing = futures::sink::unfold(client, |client, message: Msg<M>| async move {
        let serialized = serde_json::to_string(&message).context("serialize message")?;
        client
            .broadcast(&serialized)
            .await
            .context("broadcast message")?;
        Ok::<_, anyhow::Error>(client)
    });

    Ok((index, incoming, outgoing))
}

pub struct SmClient {
    request_id: String,
    token: String,
    http_client: surf::Client,
}

impl SmClient {
    pub fn new(request_id: &str, token: &str, address: surf::Url, room_id: &str) -> Result<Self> {
        let config = surf::Config::new()
            .set_base_url(address.join(&format!("rooms/{}/", room_id))?)
            .set_timeout(None);
        Ok(Self {
            request_id: request_id.to_owned(),
            token: token.to_owned(),
            http_client: config.try_into()?,
        })
    }

    pub async fn issue_index(&self, message: &str) -> Result<u16> {
        let response = self
            .http_client
            .post("issue_unique_idx")
            .header("Content-Type", "application/json")
            .header("X-Request-ID", self.request_id.as_str())
            .header("X-Token", self.token.as_str())
            .body(message)
            .recv_json::<IssuedUniqueIdx>()
            .await
            .map_err(|e| e.into_inner())?;
        Ok(response.unique_idx)
    }

    pub async fn broadcast(&self, message: &str) -> Result<()> {
        self.http_client
            .post("broadcast")
            .header("X-Request-ID", self.request_id.as_str())
            .header("X-Token", self.token.as_str())
            .body(message)
            .await
            .map_err(|e| e.into_inner())?;
        Ok(())
    }

    pub async fn subscribe(&self) -> Result<impl Stream<Item = Result<String>>> {
        let response = self
            .http_client
            .get("subscribe")
            .header("X-Request-ID", self.request_id.as_str())
            .header("X-Token", self.token.as_str())
            .await
            .map_err(|e| e.into_inner())?;
        let events = async_sse::decode(response);
        Ok(events.filter_map(|msg| async {
            match msg {
                Ok(async_sse::Event::Message(msg)) => Some(
                    String::from_utf8(msg.into_bytes())
                        .context("SSE message is not valid UTF-8 string"),
                ),
                Ok(_) => {
                    // ignore other types of events
                    None
                }
                Err(e) => Some(Err(e.into_inner())),
            }
        }))
    }
}

#[derive(Deserialize, Debug)]
struct IssuedUniqueIdx {
    unique_idx: u16,
}

#[derive(StructOpt, Debug)]
enum Cmd {
    Subscribe,
    Broadcast {
        #[structopt(short, long)]
        message: String,
    },
    IssueIdx,
}
