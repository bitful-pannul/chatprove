use frankenstein::TelegramApi;
use frankenstein::{ChatId, SendMessageParams};
use kinode_process_lib::{await_message, call_init, println, Address, Message};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use sp1_core::{utils::BabyBearBlake3, SP1ProofWithIO, SP1Prover, SP1Stdin, SP1Verifier};
use std::collections::HashMap;

use frankenstein::UpdateContent::Message as TgMessage;
mod tg_api;
use tg_api::{init_tg_bot, Api, TgResponse};

const CHAT_ELF: &[u8] = include_bytes!("../../pkg/riscv32im-succinct-zkvm-elf");

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub sender: String,
    pub text: String,
    pub timestamp: u64,
}

type Checkpoints = HashMap<u64, (Vec<u8>, Vec<ChatMessage>)>;

fn handle_message(
    api: &Api,
    worker: &Address,
    history: &mut Vec<ChatMessage>,
    last_checkpoint: &mut u64,
    checkpoints: &Checkpoints,
) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
    let message = await_message()?;

    match message {
        Message::Response { .. } => {
            return Err(anyhow::anyhow!("unexpected Response: {:?}", message));
        }
        Message::Request {
            ref source,
            ref body,
            ..
        } => match serde_json::from_slice(body) {
            Ok(TgResponse::Update(tg_update)) => {
                let updates = tg_update.updates;
                // assert update is from our worker
                if source != worker {
                    return Err(anyhow::anyhow!(
                        "unexpected source: {:?}, expected: {:?}",
                        source,
                        worker
                    ));
                }

                if let Some(update) = updates.last() {
                    match &update.content {
                        TgMessage(msg) => {
                            // if /prove command then prove that search string was within the chat history
                            if msg
                                .text
                                .as_ref()
                                .map(|s| s.starts_with("/prove"))
                                .unwrap_or(false)
                            {
                                let search_string = msg.text.as_ref().map(|s| {
                                    s.split_whitespace().skip(1).collect::<Vec<&str>>().join("")
                                });

                                let text = search_string.unwrap_or_else(|| "".to_string());

                                let mut stdin = SP1Stdin::new();
                                println!("created spi");
                                stdin.write(checkpoints);
                                println!("wrote checkpoints");
                                stdin.write(&text);
                                println!("wrote text");
                                let mut res = SP1Prover::prove(CHAT_ELF, stdin)
                                    .map_err(|e| anyhow::anyhow!(e))?;
                                println!("proven???");
                                let output = res.stdout.read::<bool>();
                                println!("output: {:?}", output);

                                let output_text = serde_json::json!(output).to_string();
                                let output_text = format!("got some proof! {}", output_text);

                                let params = SendMessageParams {
                                    chat_id: ChatId::Integer(msg.chat.id),
                                    text: output_text,
                                    parse_mode: None,
                                    disable_notification: None,
                                    reply_markup: None,
                                    entities: None,
                                    link_preview_options: None,
                                    message_thread_id: None,
                                    protect_content: None,
                                    reply_parameters: None,
                                };
                                api.send_message(&params)?;
                            }

                            let chat_message = ChatMessage {
                                sender: msg
                                    .from
                                    .as_ref()
                                    .and_then(|user| user.username.clone())
                                    .unwrap_or_else(|| "".to_string()),
                                text: msg.text.clone().unwrap_or_else(|| "".to_string()),
                                timestamp: msg.date,
                            };
                            let timestamp = chat_message.timestamp;

                            history.push(chat_message);

                            if timestamp - 5 > *last_checkpoint {
                                let mut hasher = Sha256::new();
                                hasher.update(serde_json::to_vec(&history)?);

                                let hash: Vec<u8> = hasher.finalize().to_vec();

                                *last_checkpoint = timestamp;
                                return Ok(Some((*last_checkpoint, hash)));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        },
    }
    Ok(None)
}

call_init!(init);

fn init(our: Address) {
    println!("chatproof: begin");

    let message = await_message().unwrap();
    let token_str = String::from_utf8(message.body().to_vec()).unwrap_or_else(|_| "".to_string());

    let (api, worker) = init_tg_bot(our.clone(), &token_str, None).unwrap();

    let mut history: Vec<ChatMessage> = Vec::new();

    let mut last_checkpoint: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let mut checkpoints: Checkpoints = HashMap::new();

    loop {
        match handle_message(
            &api,
            &worker,
            &mut history,
            &mut last_checkpoint,
            &checkpoints,
        ) {
            Ok(Some((timestamp, hash))) => {
                checkpoints.insert(timestamp, (hash, history));
                history = Vec::new();
            }
            Ok(None) => {}
            Err(e) => {
                println!("chatproof: error: {:?}", e);
            }
        };
    }
}

// p1 - p2 dm
// m1 m2 m3 m4 -> Hash() -> post
//    m2          Hash() -> zk -> real.

// m1 m2
//   c1   <- hash
//   c2   <- hash
//   c3   <- hash
//   c4   <- hash

// prover <-
// takes chatlog <- hash1 assert(1) <- assert(2) <- assert(3)
//   proof = true // proof == message

// merkle tree hashing btfo
// vs zk proof
