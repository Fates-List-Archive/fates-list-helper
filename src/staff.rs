use crate::serverlist;
use serde::{Deserialize, Serialize};

type Error = crate::Error;
type Context<'a> = crate::Context<'a>;

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
struct LynxActionData {
    id: String,
    reason: String,
    action: String,
    user_id: String,
    context: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LynxActionResponse {
    reason: Option<String>,
}

async fn lynx(
    ctx: Context<'_>,
    action: LynxAction,
    id: String,
    reason: String,
) -> Result<(), Error> {
    let id_i64 = id.parse::<i64>();

    if id_i64.is_err() {
        ctx.say("ID must be a i64").await?;
        return Ok(());
    }

    let bot_id = id_i64.unwrap();

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

    let req = reqwest::Client::new()
        .post("https://lynx.fateslist.xyz/_quailfeather/kitty",)
        .header("Authorization", api_token)
        .json(&LynxActionData {
            id: bot_id.to_string(),
            user_id: ctx.author().id.to_string(),
            reason,
            context: None,
            action: action_str.to_string(),
        })
        .send()
        .await?;      
        
    let status = req.status();

    let json: LynxActionResponse = req.json().await?;

    let text = if status == reqwest::StatusCode::OK {
        json.reason.unwrap_or_else(|| "Success!".to_string())
    } else {
        json.reason.unwrap_or_else(|| "Failed!".to_string())
    }.replace("&lt", "<").replace("&gt", ">");

    ctx.say(text).await?;

    Ok(())

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
    #[description = "Bot ID"] bot_id: String,
) -> Result<(), Error> {
    lynx(
        ctx,
        LynxAction::Claim,
        bot_id,
        "STUB_REASON".to_string(),
    )
    .await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unclaim(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(
        ctx,
        LynxAction::Unclaim,
        bot_id,
        reason,
    )
    .await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn requeue(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(
        ctx,
        LynxAction::Requeue,
        bot_id,
        reason,
    )
    .await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unverify(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(
        ctx,
        LynxAction::Unverify,
        bot_id,
        reason,
    )
    .await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn approve(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(
        ctx,
        LynxAction::Approve,
        bot_id,
        reason,
    )
    .await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn deny(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxAction::Deny, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn ban(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxAction::Ban, bot_id, reason).await?;
    Ok(())
}

/// Lynx Bridge. STAFF ONLY. Used for verifying bots
#[poise::command(slash_command)]
pub async fn unban(
    ctx: Context<'_>,
    #[description = "Bot ID"] bot_id: String,
    #[description = "Reason"] reason: String,
) -> Result<(), Error> {
    lynx(ctx, LynxAction::Unban, bot_id, reason).await?;
    Ok(())
}

/// Deny and anonymize a server on server listing
#[poise::command(prefix_command, slash_command, owners_only)]
pub async fn denyserver(
    ctx: Context<'_>,
    #[description = "Guild to deny"] guild_id: String,
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
    #[description = "Guild to ban"] guild_id: String,
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
    #[description = "Guild to re-enable"] guild_id: String,
) -> Result<(), Error> {
    let guild_id: i64 = guild_id.parse()?;
    let data = ctx.data();
    serverlist::enable_server(data, guild_id).await?;
    ctx.say("Server re-enabled. Ask server admins to run ``/set`` again")
        .await?;
    Ok(())
}
