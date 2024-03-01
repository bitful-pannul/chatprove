use frankenstein::TelegramApi;
use frankenstein::UpdateContent::Message as TgMessage;
use frankenstein::{ChatId, ParseMode, SendMessageParams};
use kinode_process_lib::{
    await_message, call_init, http::bind_http_static_path, println, Address, Message,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use sp1_core::{SP1Prover, SP1Stdin};
use std::collections::HashMap;

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

/// list of results: checkpoint_timestamp, sender, text
type ProofResult = Vec<(u64, String, String)>;

type Checkpoints = HashMap<u64, (Vec<u8>, Vec<ChatMessage>)>;

fn handle_message(
    our: &Address,
    api: &Api,
    history: &mut Vec<ChatMessage>,
    last_checkpoint: &mut u64,
    checkpoints: &Checkpoints,
    url: &str,
) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
    match await_message()? {
        Message::Response { .. } => Ok(None),
        Message::Request { ref body, .. } => {
            let Ok(TgResponse::Update(tg_update)) = serde_json::from_slice(body) else {
                return Ok(None);
            };
            let Some(update) = tg_update.updates.last() else {
                return Ok(None);
            };
            let TgMessage(msg) = &update.content else {
                return Ok(None);
            };
            let Some(ref msg_text) = msg.text else {
                return Ok(None);
            };
            // if /prove command then prove that search string was within the chat history
            if msg_text.starts_with("/prove ") {
                let search_string = msg.text.as_ref().map(|s| s[7..].to_string()).unwrap();

                let filtered_checkpoints: Checkpoints = checkpoints
                    .iter()
                    .filter(|&(_, (_, messages))| {
                        messages.iter().any(|m| m.text.contains(&search_string))
                    })
                    .map(|(&k, v)| (k, v.clone()))
                    .collect();

                let mut stdin = SP1Stdin::new();
                stdin.write(&filtered_checkpoints);
                stdin.write(&search_string);
                println!("chatproof: searching chat for string \"{}\"", search_string);
                let mut res = SP1Prover::prove(CHAT_ELF, stdin).map_err(|e| anyhow::anyhow!(e))?;
                println!("proof complete");
                let output = res.stdout.read::<ProofResult>();

                if output.is_empty() {
                    api.send_message(&SendMessageParams {
                        chat_id: ChatId::Integer(msg.chat.id),
                        text: "No results found".to_string(),
                        parse_mode: None,
                        disable_notification: None,
                        reply_markup: None,
                        entities: None,
                        link_preview_options: None,
                        message_thread_id: None,
                        protect_content: None,
                        reply_parameters: None,
                    })?;
                } else {
                    // turn results vector into chat message
                    let output_text = output
                        .iter()
                        .map(|(timestamp, sender, text)| {
                            format!(
                                "{} {}: {}",
                                chrono::DateTime::<chrono::Utc>::from(
                                    std::time::UNIX_EPOCH
                                        + std::time::Duration::from_secs(*timestamp)
                                )
                                .format("%Y-%m-%d %H:%M")
                                .to_string(),
                                sender,
                                text
                            )
                        })
                        .collect::<Vec<String>>()
                        .join("\n");

                    api.send_message(&SendMessageParams {
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
                    })?;
                    let proof_id: u32 = rand::random();
                    let proof_json = serde_json::to_vec(&res)?;
                    bind_http_static_path(
                        format!("/{proof_id}"),
                        false,
                        false,
                        Some("application/json".into()),
                        proof_json,
                    )?;
                    let link = format!("{}/{}/{}", url, our.process, proof_id);
                    let proof_link = format!("<a href=\"{}\">{}</a>", link, link);
                    api.send_message(&SendMessageParams {
                        chat_id: ChatId::Integer(msg.chat.id),
                        text: proof_link,
                        parse_mode: Some(ParseMode::Html),
                        disable_notification: None,
                        reply_markup: None,
                        entities: None,
                        link_preview_options: None,
                        message_thread_id: None,
                        protect_content: None,
                        reply_parameters: None,
                    })?;
                }
                // don't save bot commands to chat history
                return Ok(None);
            }

            history.push(ChatMessage {
                sender: msg
                    .from
                    .as_ref()
                    .and_then(|user| user.username.clone())
                    .unwrap_or_else(|| "".to_string()),
                text: msg.text.clone().unwrap_or_else(|| "".to_string()),
                timestamp: msg.date,
            });

            if msg.date - 5 > *last_checkpoint {
                let mut hasher = Sha256::new();
                hasher.update(serde_json::to_vec(&history)?);

                let hash: Vec<u8> = hasher.finalize().to_vec();

                *last_checkpoint = msg.date;
                Ok(Some((*last_checkpoint, hash)))
            } else {
                Ok(None)
            }
        }
    }
}

call_init!(init);
fn init(our: Address) {
    println!("chatproof: begin");

    // first message must initialize our bot-worker
    let message: Message = await_message().unwrap();
    let token_str = String::from_utf8(message.body().to_vec()).unwrap();
    let (api, _worker) = init_tg_bot(our.clone(), &token_str, None).unwrap();

    println!("chatproof: give me a url base so I can share proofs too!");
    let message: Message = await_message().unwrap();
    let url = String::from_utf8(message.body().to_vec()).unwrap();

    let mut history: Vec<ChatMessage> = Vec::new();

    let mut last_checkpoint: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // TODO: hash this data structure and commit to it somewhere for data availability
    let mut checkpoints: Checkpoints = HashMap::new();

    loop {
        match handle_message(
            &our,
            &api,
            &mut history,
            &mut last_checkpoint,
            &checkpoints,
            &url,
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
