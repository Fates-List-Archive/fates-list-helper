use async_tungstenite::{tokio::connect_async, tungstenite::Message, tungstenite::protocol::CloseFrame, tungstenite::protocol::frame::coding::CloseCode, tungstenite::client::IntoClientRequest};
use serde::{Serialize, Deserialize};
use poise::futures_util::StreamExt;
use poise::futures_util::SinkExt;
use crate::serverlist;

type Error = crate::Error;
type Context<'a> = crate::Context<'a>;

#[derive(poise::ChoiceParameter)]
enum LynxActionType {
    Bot,
    User,
}

#[derive(Debug)]
enum LynxAction {
    Claim,
    Unclaim,
    Approve,
    Deny,
    Requeue,
    Unverify,
    Ban,
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
    context: Option<String>
}

#[derive(Serialize, Deserialize)]
struct LynxPayloadSend {
    request: String,
    action: String,
    action_data: LynxActionData,
}

async fn lynx(
    ctx: Context<'_>,
    action_type: LynxActionType,
    action: LynxAction,
    id: String,
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

    let mut req = "wss://lynx.fateslist.xyz/_ws?cli=BurdockRoot%40NODBG&plat=SQUIRREL".into_client_request()?;
    *req.uri_mut() = http::Uri::builder()
        .scheme("wss")
        .authority("lynx.fateslist.xyz")
        .path_and_query("/_ws?cli=BurdockRoot%40NODBG&plat=SQUIRREL")
        .build()
        .unwrap();
    req.headers_mut().insert("Origin", "https://lynx.fateslist.xyz".parse().unwrap());
    req.headers_mut().insert("User-Agent", "Squirrelflight/0.1".parse().unwrap());
    req.headers_mut().insert("Cookie", format!("sunbeam-session:warriorcats={}", lynx_json_b64).parse().unwrap());
    
    let (ws_stream, _) = connect_async(req).await?;

    let (mut write, mut read) = ws_stream.split();

    // Send action
    ctx.say(format!("[DEBUG] Sending request for action {:?}", action)).await?;

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

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn staff(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn claim(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Claim, bot_id, "STUB_REASON".to_string()).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unclaim(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Unclaim, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn requeue(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Requeue, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unverify(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Unverify, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn approve(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Approve, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn deny(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Deny, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn ban(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Ban, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unban(
    ctx: Context<'_>,
    #[description = "Bot ID"] 
    bot_id: String, 
    #[description = "Reason"]
    reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxActionType::Bot, LynxAction::Unban, bot_id, reason).await?;
    Ok(())
}

/// Deny and anonymize a server on server listing
#[poise::command(prefix_command, slash_command, owners_only)]
pub async fn denyserver(
    ctx: Context<'_>,
    #[description = "Guild to deny"]
    guild_id: String,
) -> Result<(), Error> {
    let guild_id: i64 = guild_id.parse()?;
    let data = ctx.data();
    serverlist::deny_server(data, guild_id).await?;
    ctx.say("Server denied. Note that denies should only be used when small changes/a warning are needed and that these can easily be undone through ``/set``").await?;
    Ok(())
}

/// Ban and anonymize a server on server listing
#[poise::command(prefix_command, slash_command, owners_only)] 
pub async fn banserver(
    ctx: Context<'_>,
    #[description = "Guild to ban"]
    guild_id: String,
) -> Result<(), Error> {
    let guild_id: i64 = guild_id.parse()?;
    let data = ctx.data();
    serverlist::ban_server(data, guild_id).await?;
    ctx.say("Server banned.").await?;
    Ok(())
}

/// Re-enables a server
#[poise::command(prefix_command, slash_command, owners_only)]
pub async fn enableserver(
    ctx: Context<'_>,
    #[description = "Guild to re-enable"]
    guild_id: String,
) -> Result<(), Error> {
    let guild_id: i64 = guild_id.parse()?;
    let data = ctx.data();
    serverlist::enable_server(data, guild_id).await?;
    ctx.say("Server re-enabled. Ask server admins to run ``/set`` again").await?;
    Ok(())
}
