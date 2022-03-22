#![feature(async_closure)]

use poise::serenity_prelude as serenity;
use log::{debug, info, error};
use std::fs::File;
use std::io::Read;
use std::env;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use sqlx::postgres::PgPoolOptions;
use std::process::Command;
use std::time::Duration;
use tokio::{task, time};
use std::sync::Arc;
use poise::serenity_prelude::Mentionable;
use async_tungstenite::{tokio::connect_async, tungstenite::Message, tungstenite::protocol::CloseFrame, tungstenite::protocol::frame::coding::CloseCode, tungstenite::client::IntoClientRequest};
use poise::futures_util::StreamExt;
use poise::futures_util::SinkExt;

struct Data {pool: sqlx::PgPool, client: reqwest::Client, key_data: KeyData}
type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

/// Display your or another user's account creation date. Is a test command
#[poise::command(prefix_command, slash_command)]
async fn accage(
    ctx: Context<'_>,
    #[description = "Selected user"] user: Option<serenity::User>,
) -> Result<(), Error> {
    let user = user.as_ref().unwrap_or_else(|| ctx.author());
    ctx.say(format!("{}'s account was created at {}", user.name, user.created_at())).await?;

    Ok(())
}

/// Votes for a bot. Takes a bot as its only parameter
#[poise::command(prefix_command, slash_command, track_edits)]
async fn vote(
    ctx: Context<'_>,
    #[description = "Bot to vote for"] bot: serenity::User,
) -> Result<(), Error> {
    if !bot.bot {
        ctx.say(format!("{} is not a bot!", bot.name)).await?;
        return Ok(());
    }

    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT api_token FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if row.is_err() {
        ctx.say("You need to login to the site first!").await?;
        return Ok(());
    }

    let token = row.unwrap().api_token;

    let req = data.client.patch(
        format!("https://api.fateslist.xyz/users/{}/bots/{}/votes?test=false", ctx.author().id, bot.id)
    )
    .header("Authorization", token)
    .send()
    .await;

    if req.is_err() {
        ctx.say("Failed to vote for the bot. Please try again later.").await?;
        return Ok(());
    }

    let resp = req.unwrap();

    let status = resp.status();

    let json = resp.json::<serde_json::Value>().await?;

    if status == reqwest::StatusCode::OK {
        ctx.send(|m| {
            m.content(format!("You have successfully voted for {}", bot.name)).components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}", ctx.author().id, bot.id))
                    })
                })
            })
        }).await?;
    } else {
        ctx.send(|m| {
            m.content(format!("**Error when voting for {}:** {}", bot.name, json["reason"].as_str().unwrap_or("Unknown error"))).components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}", ctx.author().id, bot.id))
                    })
                })
            })
        }).await?;
    }

    Ok(())
}

/// Information on our new server list.
#[poise::command(prefix_command, track_edits, slash_command)]
async fn serverlist(ctx: Context<'_>)  -> Result<(), Error> {
    ctx.say("Please consider trying out ``Fates List Server Listing`` at https://fateslist.xyz/frostpaw/add-server!").await?;

    Ok(())
}

#[derive(poise::ChoiceParameter)]
enum LynxActionType {
    #[name = "bot"] 
    Bot,
    #[name = "user"] 
    User,
}

#[derive(poise::ChoiceParameter, Debug)]
enum LynxAction {
    #[name = "Claim"] 
    Claim,
    #[name = "Unclaim"] 
    Unclaim,
    #[name = "Approve"]
    Approve,
    #[name = "Deny"]
    Deny,
    #[name = "Requeue"]
    Requeue,
    #[name = "Unverify"]
    Unverify,
    #[name = "Ban"]
    Ban,
    #[name = "Unban"]
    Unban,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum LynxPayload {
    RespError {
        resp: String,
        detail: String,
    },
    RespWithScript {
        resp: String,
        script: String
    },
    PlainResp {
        resp: String,
    },
    DetailOnly {
        detail: String
    },
    // Internal parse error
    InternalParseError {
        error: String,
    }
}

#[derive(Serialize, Deserialize)]
struct LynxActionData {
    bot_id: Option<String>,
    user_id: Option<String>,
    reason: String,
    csrf_token: String,
    context: Option<String>
}

#[derive(Serialize, Deserialize)]
struct LynxPayloadSend {
    request: String,
    action: String,
    action_data: LynxActionData,
}

/// Lynx Bridge. STAFF ONLY
#[poise::command(prefix_command, track_edits, slash_command)]
async fn lynx(
    ctx: Context<'_>,
    #[description = "Action type"]
    action_type: LynxActionType,
    #[description = "Action on Lynx"]
    action: LynxAction,
    #[description = "ID"]
    id: String,
    #[description = "Reason"]
    reason: String,
)  -> Result<(), Error> {

    let id_i64 = id.parse::<i64>();

    if id_i64.is_err() {
        ctx.say("ID must be a i64").await?;
        return Ok(())
    }

    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT api_token FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if row.is_err() {
        ctx.say("Unauthorized").await?;
        return Ok(());
    }

    let api_token = row.unwrap().api_token;

    // Now create WS connection
    let lynx_json = serde_json::json!({
        "user": {
            "id": ctx.author().id.0.to_string(),
            "username": "Squirrelflight-Virtual",
            "disc": "0000",
            "avatar": "https://cdn.discordapp.com/avatars/723456789012345678/723456789012345678.png?size=1024",
            "bot": false,
            "status": "Unknown",
        },
        "token": api_token,
    });

    let lynx_json_val = serde_json::to_string(&lynx_json).unwrap();
    let lynx_json_b64 = base64::encode(lynx_json_val);

    ctx.say("[DEBUG] Connecting to Lynx...").await?;

    let mut req = "wss://lynx.fateslist.xyz/_ws".into_client_request()?;
    req.headers_mut().insert("Origin", "https://lynx.fateslist.xyz".parse().unwrap());
    req.headers_mut().insert("User-Agent", "Squirrelflight/0.1".parse().unwrap());
    req.headers_mut().insert("Cookie", format!("sunbeam-session:warriorcats={}", lynx_json_b64).parse().unwrap());
    
    let (ws_stream, _) = connect_async(req).await?;

    let (mut write, mut read) = ws_stream.split();

    let first = read.next().await;

    if first.is_none() {
        ctx.say("[ERROR] Failed to connect to Lynx").await?;
        return Ok(());
    }

    let action_str = match action_type {
        LynxActionType::Bot => "bot_actions",
        LynxActionType::User => "user_actions",
    };

    // Send message
    ctx.say(format!("[DEBUG] Requesting for page {} for CSRF validation", action_str)).await?;


    // No need to keep recreating this string
    let actions_msg = match action_type {
        LynxActionType::Bot => "{\"request\":\"bot_actions\"}".to_string(),
        LynxActionType::User => "{\"request\":\"user_actions\"}".to_string(),
    };
    write.send(Message::Text(actions_msg)).await?;

    let script_data: String;

    loop {
        let msg = read.next().await;

        if msg.is_none() {
            continue;
        }
        let msg = msg.unwrap();
        if msg.is_err() {
            // Close the conn
            ctx.say("[ERROR] Lynx connection closed (reason=ErrWsMsg)...").await?;
            write.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "Squirrelflight Command Error".into(),
            }))).await?;
            return Ok(())
        }

        let msg = msg.unwrap();

        let csrf_msg = match msg {
            Message::Text(msg) => msg,
            Message::Ping(_) => {
                write.send(Message::Pong(Vec::new())).await?;
                continue;
            },
            _ => continue,
        };

        // Serde serialize
        let data: LynxPayload = serde_json::from_str(&csrf_msg).unwrap_or_else(|err| {
            LynxPayload::InternalParseError {
                error: format!("{:?}", err),
            }
        });

        match data {
            LynxPayload::RespError { resp, detail } => {
                ctx.say(format!("[ERROR] Failed to connect to Lynx. Error was {:?} with resp {:?}", detail, resp)).await?;
                write.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "Squirrelflight Command Done".into(),
                }))).await?;            
                return Ok(())
            },
            LynxPayload::RespWithScript { resp, script } => {
                if resp == action_str.to_string() {
                    ctx.say(format!("[DEBUG] Got {} response", action_str)).await?;
                    script_data = script;
                    break                
                }
                continue
            },
            LynxPayload::PlainResp {resp: _} => {
                continue
            },
            LynxPayload::DetailOnly { detail: _ } => {
                continue
            },
            LynxPayload::InternalParseError { error } => {
                ctx.say(format!("[ERROR] Failed to parse JSON: {:?} with original JSON of {:?}", error, csrf_msg)).await?;
                write.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "Squirrelflight Command Done".into(),
                }))).await?;            
                return Ok(())
            },
        }
    }

    let csrf_token = script_data.split("csrfToken").nth(1).unwrap_or_default();

    let csrf_token = csrf_token.split("\"").nth(1).unwrap().replace("\\", "");

    // Send csrfToken
    ctx.say(format!("Sending request for action {:?} with csrf token of {:?}", action, csrf_token)).await?;
    debug!("{:?}", csrf_token);

    let action_type_send = match action_type {
        LynxActionType::Bot => "bot_action".to_string(),
        LynxActionType::User => "user_action".to_string(),
    };

    let action_str = match action {
        LynxAction::Claim => "claim",
        LynxAction::Unclaim => "unclaim",
        LynxAction::Approve => "approve",
        LynxAction::Deny => "deny",
        LynxAction::Requeue => "requeue",
        LynxAction::Unverify => "unverify",
        LynxAction::Ban => "ban",
        LynxAction::Unban => "unban",
    };

    let mut action_dat = LynxPayloadSend {
        request: action_type_send.clone(),
        action: action_str.to_string(),
        action_data: LynxActionData {
            bot_id: None,
            user_id: None,
            context: None,
            reason,
            csrf_token,
        },
    };

    match action_type {
        LynxActionType::Bot => {
            action_dat.action_data.bot_id = Some(id);
        },
        LynxActionType::User => {
            action_dat.action_data.user_id = Some(id);
        },
    }

    // JSON serialize and send, then wait for next event
    write.send(Message::Text(serde_json::to_string(&action_dat).unwrap())).await?;

    loop {
        let msg = read.next().await;

        if msg.is_none() {
            continue;
        }
        let msg = msg.unwrap();
        if msg.is_err() {
            // Close the conn
            ctx.say("[ERROR] Lynx connection closed (reason=ErrWsMsg)...").await?;
            write.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "Squirrelflight Command Error".into(),
            }))).await?;
            return Ok(())
        }

        let msg = msg.unwrap();

        let resp_msg = match msg {
            Message::Text(msg) => msg,
            Message::Ping(_) => {
                write.send(Message::Pong(Vec::new())).await?;
                continue;
            },
            _ => continue,
        };

        // Serde serialize
        let data: LynxPayload = serde_json::from_str(&resp_msg).unwrap_or_else(|err| {
            LynxPayload::InternalParseError {
                error: format!("{:?}", err),
            }
        });
        
        match data {
            LynxPayload::RespError {resp, detail} => {
                if resp != action_type_send {
                    continue
                }
                ctx.say(format!("[RESPONSE] {:?}", detail)).await?;
                write.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "Squirrelflight Command Done".into(),
                }))).await?;            
                return Ok(())
            },
            _ => continue
        }
    }
}

/// Show this help menu
#[poise::command(prefix_command, track_edits, slash_command)]
async fn help(
    ctx: Context<'_>,
    #[description = "Specific command to show help about"]
    #[autocomplete = "poise::builtins::autocomplete_command"]
    command: Option<String>,
) -> Result<(), Error> {
    poise::builtins::help(
        ctx,
        command.as_deref(),
        poise::builtins::HelpConfiguration {
            extra_text_at_bottom: "\
Squirrelflight Help. Ask on our support server for more information\n",
            show_context_menu_commands: true,
            ..poise::builtins::HelpConfiguration::default()
        },
    )
    .await?;
    Ok(())
}

/// Returns version information
#[poise::command(prefix_command, slash_command)]
async fn about(ctx: Context<'_>) -> Result<(), Error> {
    let git_commit_hash = Command::new("git")
    .args(["rev-parse", "HEAD"]).output();

    let hash: String;

    if git_commit_hash.is_err() {
        hash = "Unknown".to_string();
    } else {
        hash = String::from_utf8(git_commit_hash.unwrap().stdout).unwrap_or_else(|_| "Unknown (utf8 parse failure)".to_string());
    }
    ctx.say(format!("Squirrelflight v0.1.0\n\n**Commit Hash:** {}", hash)).await?;
    Ok(())
}

/// See the bot queue so you know exactly where you're bot is!
#[poise::command(prefix_command, slash_command, track_edits)]
async fn queue(ctx: Context<'_>) -> Result<(), Error> {
    let data = ctx.data();

    let rows = sqlx::query!(
        "SELECT username_cached, bot_id, description FROM bots WHERE state = 1 ORDER BY created_at ASC",
    )
    .fetch_all(&data.pool)
    .await;

    if rows.is_err() {
        ctx.say("There was an error fetching the queue. Please try again later.").await?;
        return Ok(());
    }

    let rows = rows.unwrap();

    let mut desc = "*Does not take into account bots that are currently under review*\n".to_string();

    let mut i = 1;

    for row in rows {
        let mut name = row.username_cached.unwrap_or_else(|| "Username not cached".to_string());
        if name.is_empty() {
            name = "Username not cached".to_string();
        }

        desc += format!("\n**{i}. {name}** - [View On Site](https://fateslist.xyz/bot/{invite})\n{desc}", i=i, name=name, invite=row.bot_id, desc=row.description.unwrap_or_default()).as_str();
    
        i += 1;
    }

    desc += "\n\n**Note to staff: Always see site pages before approving or even testing a bot!**";

    ctx.send(|m| {
        m.embed(|e| {
            e.title("**Bot Queue**");
            e.description(desc)
        })
    }).await?;

    Ok(())
}

/// Register application commands in this guild or globally
///
/// Run with no arguments to register in guild, run with argument "global" to register globally.
#[poise::command(prefix_command, hide_in_help, owners_only, track_edits)]
async fn register(ctx: Context<'_>, #[flag] global: bool) -> Result<(), Error> {
    poise::builtins::register_application_commands(ctx, global).await?;

    Ok(())
}

// Internal Secrets Struct
#[derive(Deserialize)]
pub struct Secrets {
    pub token_squirrelflight: String,
}

#[derive(Deserialize, Clone)]
pub struct KeyChannels {
    vote_reminder_channel: serenity::model::id::ChannelId,
}

#[derive(Deserialize, Clone)]
pub struct KeyData {
    channels: KeyChannels,
}

fn get_data_dir() -> String {
    let path = match env::var_os("HOME") {
        None => { panic!("$HOME not set"); }
        Some(path) => PathBuf::from(path),
    };    

    let data_dir = path.into_os_string().into_string().unwrap() + "/FatesList/config/data/";

    debug!("Data dir: {}", data_dir);

    data_dir
}

fn get_bot_token() -> String {
    let data_dir = get_data_dir();

    // open secrets.json, handle config
    let mut file = File::open(data_dir + "secrets.json").expect("No config file found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let secrets: Secrets = serde_json::from_str(&data).expect("JSON was not well-formatted");

    secrets.token_squirrelflight
}

fn get_key_data() -> KeyData {
    let data_dir = get_data_dir();

    // open discord.json, handle config
    let mut file = File::open(data_dir + "discord.json").expect("No config file found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let data: KeyData = serde_json::from_str(&data).expect("Discord JSON was not well-formatted");

    data
}

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    // This is our custom error handler
    // They are many errors that can occur, so we only handle the ones we want to customize
    // and forward the rest to the default handler
    match error {
        poise::FrameworkError::Setup { error } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx } => {
            error!("Error in command `{}`: {:?}", ctx.command().name, error,);
            ctx.say(format!("There was an error running this command: {:?}", error)).await.unwrap();
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                error!("Error while handling error: {}", e);
            }
        }
    }
}

async fn event_listener(
    ctx: &serenity::Context,
    event: &poise::Event<'_>,
    _framework: &poise::Framework<Data, Error>,
    user_data: &Data,
) -> Result<(), Error> {
    match event {
        poise::Event::Ready { data_about_bot } => {
            info!("{} is connected!", data_about_bot.user.name);

            let ctx = ctx.to_owned();
            let pool = user_data.pool.clone();
            let key_data = user_data.key_data.clone();

            task::spawn(async move {
                vote_reminder_task(pool, key_data, ctx.http).await;
            });
        }
        poise::Event::InteractionCreate { interaction } => {
            let msg_inter = interaction.clone().message_component();
            if msg_inter.is_some() {
                let msg_inter = msg_inter.unwrap();
                // Now get the custom id
                let custom_id = msg_inter.data.custom_id.clone();
                if custom_id.starts_with("vrtoggle-") {
                    let parts: Vec<&str> = custom_id.split('-').collect();
                    if parts.len() != 3 {
                        return Ok(());
                    }
                    let user_id = parts[1].parse::<i64>();
                    let bot_id = parts[2].parse::<i64>();
                    if user_id.is_ok() && bot_id.is_ok() {
                        let user_id = user_id.unwrap();
                        let bot_id = bot_id.unwrap();
                    
                        let author = msg_inter.user.id.0 as i64;

                        if user_id != author {
                            return Ok(());
                        }

                        // Check if they've signed up for VR already
                        let row = sqlx::query!(
                            "SELECT vote_reminders FROM users WHERE user_id = $1",
                            user_id
                        )
                        .fetch_one(&user_data.pool)
                        .await;
                        
                        match row.as_ref().err() {
                            Some(sqlx::Error::RowNotFound) => {
                                debug!("Choosing VR path RowInsert");
                                sqlx::query!(
                                    "INSERT INTO users (user_id, vote_reminders) VALUES ($1, $2)",
                                    user_id,
                                    &vec![bot_id]
                                )
                                .execute(&user_data.pool)
                                .await?;
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content("You have successfully subscribed to vote reminders!");
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            },
                            None => {
                                debug!("Choosing VR path RowUpdate");
                                
                                let row = row.unwrap();
                                for bot in row.vote_reminders {
                                    if bot == bot_id {
                                        msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                            m.interaction_response_data(|m| {
                                                m.content("You have already subscribed to vote reminders for this bot!");
                                                m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);
        
                                                m
                                            })
                                        }).await?; 
                                        return Ok(());       
                                    }
                                }

                                sqlx::query!(
                                    "UPDATE users SET vote_reminders = vote_reminders || $2 WHERE user_id = $1",
                                    user_id,
                                    &vec![bot_id]
                                )
                                .execute(&user_data.pool)
                                .await?;
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content("You have successfully subscribed to vote reminders!");
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            },
                            Some(err) => {
                                // Odd error, lets return it
                                error!("{}", err);
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content(format!("**Error:** {}", err));
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

async fn vote_reminder_task(pool: sqlx::PgPool, key_data: KeyData, http: Arc<serenity::http::Http>) {
    let mut interval = time::interval(Duration::from_millis(10000));

    loop {
        interval.tick().await;
        debug!("Called VRTask"); // TODO: Remove this

        let rows = sqlx::query!(
            "SELECT user_id, vote_reminders, vote_reminder_channel FROM users 
            WHERE cardinality(vote_reminders) > 0 
            AND NOW() - vote_reminders_last_acked > interval '4 hours'"
        )
        .fetch_all(&pool)
        .await;

        if rows.is_err() {
            error!("{}", rows.err().unwrap());
            continue;
        }

        let rows = rows.unwrap();

        for row in rows {
            // If a user can't vote for one bot, they can't vote for any
            let count = sqlx::query!(
                "SELECT COUNT(1) FROM user_vote_table WHERE user_id = $1",
                row.user_id
            )
            .fetch_one(&pool)
            .await;

            if count.is_err() {
                continue
            } else if count.unwrap().count.unwrap_or_default() > 0 {
                continue
            }

            let mut channel: serenity::model::id::ChannelId = key_data.channels.vote_reminder_channel;
            if row.vote_reminder_channel.is_some() {
                channel = serenity::model::id::ChannelId(row.vote_reminder_channel.unwrap().try_into().unwrap_or(key_data.channels.vote_reminder_channel.0));
            }

            // The hard part, bot string creation

            let mut bots_str: String = "".to_string();

            // tlen contains the total length of the vote reminders
            // If tlen is one and was always one then we don't need to add a comma
            let tlen_initial = row.vote_reminders.len();
            let mut tlen = row.vote_reminders.len();

            for bot in &row.vote_reminders {
                let mut mod_front = "";
                if tlen_initial > 1 && tlen == 1 {
                    // We have more than one bot, but we're at the last one
                    mod_front = " and ";
                } else if tlen_initial > 1 && tlen > 1 {
                    // We have more than one bot, and we're not at the last one
                    mod_front = ", ";
                }

                bots_str += format!("{mod_front}<@{bot}> ({bot})", bot = bot, mod_front = mod_front).as_str();

                tlen -= 1;
            }

            // Now actually send the message
            let res = channel.send_message(http.clone(), |m| {

                m.content(
                    format!(
                        "Hey {user}, you can vote for {bots} or did you forget?",
                        user = serenity::model::id::UserId(row.user_id as u64).mention(),
                        bots = bots_str
                    ));

                m
            })
            .await;

            if res.is_err() {
                error!("Message send error: {}", res.err().unwrap());
            }

            debug!("User {} with bots {:?}", row.user_id, row.vote_reminders);

            // Reack
            let reack = sqlx::query!(
                "UPDATE users SET vote_reminders_last_acked = NOW() WHERE user_id = $1",
                row.user_id
            )
            .execute(&pool)
            .await;

            if reack.is_err() {
                error!("Reack error: {}", reack.err().unwrap());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    const MAX_CONNECTIONS: u32 = 3; // max connections to the database, we don't need too many here

    std::env::set_var("RUST_LOG", "squirrelflight=debug");
    env_logger::init();
    info!("Starting Squirrelfight...");

    let client = reqwest::Client::builder()
    .user_agent("FatesList-Squirrelflight/1.0 (internal microservice)")
    .build()
    .unwrap();

    poise::Framework::build()
        .token(get_bot_token())
        .user_data_setup(move |_ctx, _ready, _framework| Box::pin(async move {
            Ok(Data {
                pool: PgPoolOptions::new()
                .max_connections(MAX_CONNECTIONS)
                .connect("postgres://localhost/fateslist")
                .await
                .expect("Could not initialize connection"),
                key_data: get_key_data(),
                client,
            })
        }))
        .options(poise::FrameworkOptions {
            // configure framework here
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("+".into()),
                ..poise::PrefixFrameworkOptions::default()
            },
            /// This code is run before every command
            pre_command: |ctx| {
                Box::pin(async move {
                    info!("Executing command {} for user {} ({})...", ctx.command().qualified_name, ctx.author().name, ctx.author().id);
                })
            },
            /// This code is run after every command returns Ok
            post_command: |ctx| {
                Box::pin(async move {
                    info!("Done executing command {} for user {} ({})...", ctx.command().qualified_name, ctx.author().name, ctx.author().id);
                })
            },
            on_error: |error| Box::pin(on_error(error)),
            listener: |ctx, event, framework, user_data| { 
                Box::pin(event_listener(ctx, event, framework, user_data))
            },
            commands: vec![accage(), vote(), help(), register(), about(), queue(), serverlist(), lynx()],
            ..poise::FrameworkOptions::default()
        })
        .run().await.unwrap();
}
