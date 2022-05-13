use crate::helpers;
use bristlefrost::models::{Flags, LongDescriptionType, State, WebhookType};
use poise::serenity_prelude as serenity;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::json;
use std::borrow::Cow;

type Error = crate::Error;
type Context<'a> = crate::Context<'a>;
type Data = crate::Data;

/// Deletes the server from Fates List Server Listing
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "ADMINISTRATOR"
)]
pub async fn delserver(ctx: Context<'_>) -> Result<(), Error> {
    let guild = ctx.guild();

    let data = ctx.data();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    sqlx::query!("DELETE FROM servers WHERE guild_id = $1", guild.id.0 as i64)
        .execute(&data.pool)
        .await?;

    sqlx::query!("DELETE FROM vanity WHERE redirect = $1", guild.id.0 as i64)
        .execute(&data.pool)
        .await?;

    ctx.say("Server deleted. Feel free to kick the bot").await?;

    Ok(())
}

/// Tag base command
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "SEND_MESSAGES"
)]
pub async fn tags(ctx: Context<'_>) -> Result<(), Error> {
    ctx.say("Available options are ``tags add``, ``tags dump``, ``tags remove``, ``tags edit``, ``tags nuke`` and ``tags transfer``. *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*").await?;
    Ok(())
}

/// Adds a tag
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "add"
)]
pub async fn tag_add(
    ctx: Context<'_>,
    #[description = "Tag name"] tag_name: String,
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let sanitized = tag_name
        .chars()
        .filter(|&c| c.is_alphabetic() || c == ' ')
        .collect::<String>();

    if sanitized != tag_name {
        ctx.say("Tag name contains invalid characters. Only a-z and spaces are allowed.")
            .await?;
        return Ok(());
    }

    let banned = vec![
        "best-",
        "good-",
        "fuck",
        "nigger",
        "fates-list",
        "fateslist",
    ];

    for kw in banned {
        if tag_name.contains(kw) {
            ctx.say(&format!("{} not allowed in tag names", kw)).await?;
            return Ok(());
        }
    }

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            sqlx::query!(
                "INSERT INTO server_tags (id, name, iconify_data, owner_guild) VALUES ($1, $2, $3, $4)",
                internal_tag_name,
                tag_name,
                "fluent:animal-cat-28-regular",
                guild.id.0 as i64,
            )
            .execute(&data.pool)
            .await?;

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_append(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!("Tag {} added and ownership claimed as this is a brand new tag! *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*", tag_name)).await?;
        }
        Err(e) => {
            return Err(Box::new(e));
        }
        Ok(row) => {
            // Check if tag already exists
            let check = sqlx::query!(
                "SELECT tags FROM servers WHERE guild_id = $1",
                guild.id.0 as i64
            )
            .fetch_one(&data.pool)
            .await?;

            for tag in check.tags.unwrap_or_default() {
                if tag == internal_tag_name {
                    ctx.say(format!("Tag {} is already present on this server! *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*", tag_name)).await?;
                    return Ok(());
                }
            }

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_append(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            let mut owner_guild = row.owner_guild;

            if owner_guild == 0 {
                // We have a unclaimed tag, claim it
                sqlx::query!(
                    "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                    guild.id.0 as i64,
                    internal_tag_name
                )
                .execute(&data.pool)
                .await?;
                owner_guild = guild.id.0 as i64;
            }

            ctx.say(format!("Tag {} added. The current owner server of this tag is {}. You can get detailed tag information using ``tag dump``! *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*", tag_name, owner_guild)).await?;
        }
    }

    Ok(())
}

/// Edits a tag
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "edit"
)]
pub async fn tag_edit(
    ctx: Context<'_>,
    #[description = "Tag name"] tag_name: String,
    #[description = "New iconify icon (see https://iconify.design)"] iconify_data: String,
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        }
        Err(e) => {
            return Err(Box::new(e));
        }
        Ok(row) => {
            if row.owner_guild != guild.id.0 as i64 {
                ctx.say(format!("You do not own tag {} and as such you may not modify its properties.\n\nContact Fates List Staff if you think this server is holding the tag for malicious purposes and does not allow for sane discussion over it. *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*", tag_name)).await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE server_tags SET iconify_data = $1 WHERE id = $2",
                iconify_data,
                internal_tag_name
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!("Tag {} updated! *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*", tag_name)).await?;
        }
    }

    Ok(())
}

/// Nukes a tag if it is only present in one or less servers
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "nuke"
)]
pub async fn tag_nuke(
    ctx: Context<'_>,
    #[description = "Tag name"] tag_name: String,
) -> Result<(), Error> {
    let data = ctx.data();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT guild_id FROM servers WHERE tags && $1",
        &vec![internal_tag_name.clone()]
    )
    .fetch_all(&data.pool)
    .await?;

    if check.len() > 1 {
        ctx.say(format!(
            "Tag {} is present on more than one server and cannot be nuked: {:?}.",
            tag_name, check
        ))
        .await?;
        return Ok(());
    }

    sqlx::query!("DELETE FROM server_tags WHERE id = $1", internal_tag_name)
        .execute(&data.pool)
        .await?;

    sqlx::query!(
        "UPDATE servers SET tags = array_remove(tags, $1)",
        internal_tag_name
    )
    .execute(&data.pool)
    .await?;

    ctx.say("Tag nuked!").await?;

    Ok(())
}

/// Transfers a tag
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "transfer"
)]
pub async fn tag_transfer(
    ctx: Context<'_>,
    #[description = "Tag name"] tag_name: String,
    #[description = "New server. Set to 'unclaim' to unclaim the tag. A unclaimed tag may be claimed by adding it."]
    new_server: String,
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        }
        Err(e) => {
            return Err(Box::new(e));
        }
        Ok(row) => {
            if row.owner_guild != guild.id.0 as i64 {
                ctx.say(format!("You do not own tag {} and as such you may not modify its properties.\n\nContact Fates List Staff if you think this server is holding the tag for malicious purposes and does not allow for sane discussion over it.", tag_name)).await?;
                return Ok(());
            }

            if new_server == "unclaim" {
                // Remove tag claim
                sqlx::query!(
                    "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                    0,
                    internal_tag_name
                )
                .execute(&data.pool)
                .await?;

                ctx.say(format!("Tag {} unclaimed!", tag_name)).await?;

                return Ok(());
            }

            let new_server_id = match new_server.parse::<i64>() {
                Ok(id) => id,
                Err(_) => {
                    ctx.say(format!("Server {} is not a i64", new_server))
                        .await?;
                    return Ok(());
                }
            };

            let check = sqlx::query!(
                "SELECT tags FROM servers WHERE guild_id = $1",
                new_server_id
            )
            .fetch_one(&data.pool)
            .await?;

            for tag in check.tags.unwrap_or_default() {
                if tag == internal_tag_name {
                    sqlx::query!(
                        "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                        new_server_id,
                        internal_tag_name
                    )
                    .execute(&data.pool)
                    .await?;

                    ctx.say(format!("Tag {} transferred!", tag_name)).await?;
                    return Ok(());
                }
            }
            ctx.say(format!(
                "Tag {} could not be transferred as recipient server does not also have tag!",
                tag_name
            ))
            .await?;
        }
    }

    Ok(())
}

/// Dumps a tag
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "dump"
)]
pub async fn tag_dump(
    ctx: Context<'_>,
    #[description = "Tag name or internal name"] tag_name: String,
) -> Result<(), Error> {
    let data = ctx.data();

    // Dump tag table
    let row = sqlx::query!(
        "SELECT to_json(server_tags) AS json FROM server_tags WHERE id = $1 OR name = $1",
        tag_name
    )
    .fetch_one(&data.pool)
    .await?;

    let data = serde_json::to_string_pretty(&row.json)?;

    // Get around attachment limitation
    ctx.defer().await?;

    ctx.send(|m| {
        m.content("Tag dump");
        m.attachment(serenity::AttachmentType::Bytes {
            data: Cow::from(data.as_bytes().to_vec()),
            filename: "tag-dump.json".to_string(),
        })
    })
    .await?;

    Ok(())
}

/// Removes a tag from a server.
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "MANAGE_GUILD",
    rename = "remove"
)]
pub async fn tag_remove(
    ctx: Context<'_>,
    #[description = "Tag name"] tag_name: String,
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        }
        Err(e) => {
            return Err(Box::new(e));
        }
        Ok(row) => {
            if row.owner_guild == guild.id.0 as i64 {
                ctx.say(format!("You currently own tag {} and as such cannot remove it. Consider transferring it to another server using ``tag transfer``. See ``help`` for more information.", tag_name)).await?;
                return Ok(());
            }

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_remove(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!(
                "Tag {} removed if present. You can use ``dumpserver`` to verify this",
                tag_name
            ))
            .await?;
        }
    }

    Ok(())
}

/// View audit logs.
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "VIEW_AUDIT_LOG"
)]
pub async fn auditlogs(ctx: Context<'_>) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    // Get around attachment limitation
    ctx.defer_ephemeral().await?;

    // Dump server table
    let row = sqlx::query!(
        "SELECT to_json(server_audit_logs) AS json FROM server_audit_logs WHERE guild_id = $1",
        guild.id.0 as i64
    )
    .fetch_all(&ctx.data().pool)
    .await?;

    let logs = Vec::from_iter(row.iter().map(|row| row.json.as_ref().unwrap()));

    let data = serde_json::to_string_pretty(&logs)?;

    ctx.send(|m| {
        m.content("**If you or any server member wishes to remove their data from 'Audit Logs', please go to https://lynx.fateslist.xyz/privacy#data-deletion-request. Audit logs are not a replacement for proper moderation**");
        m.attachment(serenity::AttachmentType::Bytes { data: Cow::from(data.as_bytes().to_vec()), filename: "audit-logs.json".to_string() } );
        m.ephemeral(true)
    }).await?;

    Ok(())
}

/// Dumps the server data to a file for viewing.
#[poise::command(
    prefix_command,
    slash_command,
    guild_cooldown = 10,
    required_permissions = "ADMINISTRATOR"
)]
pub async fn dumpserver(ctx: Context<'_>) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let member = ctx.author_member().await.unwrap();

    let guild = guild.unwrap();

    // Dump server table
    let row = sqlx::query!(
        "SELECT to_json(servers) AS json FROM servers WHERE guild_id = $1",
        guild.id.0 as i64
    )
    .fetch_one(&ctx.data().pool)
    .await?;

    let vanity = sqlx::query!(
        "SELECT to_json(vanity) AS json FROM vanity WHERE redirect = $1",
        guild.id.0 as i64
    )
    .fetch_one(&ctx.data().pool)
    .await;

    let vanity_data = match vanity {
        Ok(vanity) => vanity.json.unwrap_or_else(|| serde_json::json!({})),
        Err(sqlx::Error::RowNotFound) => {
            serde_json::json!({})
        }
        Err(e) => {
            return Err(Box::new(e));
        }
    };

    let row_json = row.json.unwrap_or_else(|| serde_json::json!({}));

    if let serde_json::Value::Object(mut v) = row_json {
        v.insert("vanity".to_string(), vanity_data);

        // Remove sensitive fields
        v.remove("webhook_secret");
        v.insert(
            "webhook_secret".to_string(),
            serde_json::json!("Redacted from server dump. Reset using /set"),
        );

        let data = serde_json::to_string_pretty(&v)?;

        member
            .user
            .create_dm_channel(&ctx.discord())
            .await?
            .send_message(&ctx.discord(), |m| {
                m.content("**Server Dump**");
                m.files(vec![serenity::AttachmentType::Bytes {
                    data: Cow::from(data.as_bytes().to_vec()),
                    filename: "server.json".to_string(),
                }])
            })
            .await?;

        ctx.say("DMed you server dump").await?;

        return Ok(());
    }

    ctx.say("Failed to dump server. Contact Fates List Support.")
        .await?;

    Ok(())
}

#[derive(poise::ChoiceParameter, Debug)]
pub enum SetField {
    #[name = "Description"]
    Description,
    #[name = "Long Description"]
    LongDescription,
    #[name = "Long Description Type"]
    LongDescriptionType,
    #[name = "Invite Code"]
    InviteCode,
    #[name = "Invite Channel ID"]
    InviteChannelID,
    #[name = "Website"]
    Website,
    #[name = "CSS"]
    Css,
    #[name = "Banner (server card)"]
    BannerCard,
    #[name = "Banner (server page)"]
    BannerPage,
    #[name = "Keep Banner Decorations"]
    KeepBannerDecor,
    #[name = "Vanity"]
    Vanity,
    #[name = "State"]
    State,
    #[name = "Webhook URL"]
    WebhookURL,
    #[name = "Webhook Type"]
    WebhookType,
    #[name = "Webhook Secret"]
    WebhookSecret,
    #[name = "Webhook HMAC Only"]
    WebhookHMACOnly,
    #[name = "Requires Login To Join"]
    RequiresLogin,
    #[name = "Vote Roles"]
    VoteRoles,
    #[name = "Whitelist Only"]
    WhitelistOnly,
    #[name = "Whitelist Form"]
    WhitelistForm, // Done till here
}

fn create_token(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub async fn deny_server(data: &Data, guild_id: i64) -> Result<(), Error> {
    sqlx::query!("UPDATE servers SET old_state = state, state = $1, name_cached = 'Unknown', avatar_cached = '' WHERE guild_id = $2", State::Denied as i32, guild_id).execute(&data.pool).await?;

    Ok(())
}

pub async fn enable_server(data: &Data, guild_id: i64) -> Result<(), Error> {
    sqlx::query!("UPDATE servers SET old_state = state, state = $1, name_cached = '', avatar_cached = '' WHERE guild_id = $2", State::Approved as i32, guild_id).execute(&data.pool).await?;

    Ok(())
}

pub async fn ban_server(data: &Data, guild_id: i64) -> Result<(), Error> {
    sqlx::query!("UPDATE servers SET old_state = state, state = $1, name_cached = 'Unknown', avatar_cached = '' WHERE guild_id = $2", State::Banned as i32, guild_id).execute(&data.pool).await?;

    Ok(())
}

#[derive(poise::ChoiceParameter, PartialEq, Debug)]
pub enum Allowlist {
    #[name = "User Whitelist"]
    Whitelist,
    #[name = "User Blacklist"]
    Blacklist,
}

#[derive(poise::ChoiceParameter, PartialEq, Debug)]
pub enum AllowlistAction {
    #[name = "Add"]
    Add,
    #[name = "Remove"]
    Remove,
    #[name = "Clear"]
    Clear,
}

/// Modify the server allow list to control who can access a server
#[poise::command(
    track_edits,
    prefix_command,
    slash_command,
    guild_cooldown = 5,
    guild_only,
    required_permissions = "ADMINISTRATOR"
)]
pub async fn allowlist(
    ctx: Context<'_>,
    #[description = "List to change"] field: Allowlist,
    #[description = "What to change"] change: AllowlistAction,
    #[description = "Member to add/remove"] user: Option<String>,
) -> Result<(), Error> {
    if user.is_none() && change != AllowlistAction::Clear {
        ctx.say("No user specified but you are asking to add/remove a user from allowlist")
            .await?;
        return Ok(());
    }

    let guild = ctx.guild().unwrap();
    let data = ctx.data();

    match field {
        Allowlist::Whitelist => match change {
            AllowlistAction::Add => {
                let user: i64 = user.unwrap().parse()?;
                sqlx::query!(
                        "UPDATE servers SET user_whitelist = array_remove(user_whitelist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
                sqlx::query!(
                        "UPDATE servers SET user_whitelist = array_append(user_whitelist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
            }
            AllowlistAction::Remove => {
                let user: i64 = user.unwrap().parse()?;
                sqlx::query!(
                        "UPDATE servers SET user_whitelist = array_remove(user_whitelist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
            }
            AllowlistAction::Clear => {
                sqlx::query!(
                    "UPDATE servers SET user_whitelist = '{}' WHERE guild_id = $1",
                    guild.id.0 as i64,
                )
                .execute(&data.pool)
                .await?;
            }
        },
        Allowlist::Blacklist => match change {
            AllowlistAction::Add => {
                let user: i64 = user.unwrap().parse()?;
                sqlx::query!(
                        "UPDATE servers SET user_blacklist = array_remove(user_blacklist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
                sqlx::query!(
                        "UPDATE servers SET user_blacklist = array_append(user_blacklist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
            }
            AllowlistAction::Remove => {
                let user: i64 = user.unwrap().parse()?;
                sqlx::query!(
                        "UPDATE servers SET user_blacklist = array_remove(user_blacklist, $1) WHERE guild_id = $2",
                        user,
                        guild.id.0 as i64,
                    )
                    .execute(&data.pool)
                    .await?;
            }
            AllowlistAction::Clear => {
                sqlx::query!(
                    "UPDATE servers SET user_blacklist = '{}' WHERE guild_id = $1",
                    guild.id.0 as i64,
                )
                .execute(&data.pool)
                .await?;
            }
        },
    }

    ctx.say("Allowlist updated").await?;

    Ok(())
}

/// Sets a field. This adds your server to the server list.
#[poise::command(
    track_edits,
    prefix_command,
    slash_command,
    guild_cooldown = 5,
    guild_only,
    required_permissions = "MANAGE_GUILD"
)]
pub async fn set(
    ctx: Context<'_>,
    #[description = "Field to set"] field: SetField,
    #[description = "(Raw) Value to set field to. 'none' to reset"] mut value: Option<String>,
    #[description = "A file containing the value to set. Overrides value"] long_value: Option<
        serenity::model::channel::Attachment,
    >,
) -> Result<(), Error> {
    let data = ctx.data();

    if long_value.is_some() {
        let long_value = long_value.unwrap();
        if !long_value.filename.ends_with(".txt") {
            ctx.say("File name must end in .txt at the time!").await?;
            return Ok(());
        }

        let download = long_value.download().await?;

        value = Some(match std::str::from_utf8(&download) {
            Ok(v) => v.to_string(),
            Err(e) => {
                ctx.say(format!("File is not a valid string: {:?}!", e))
                    .await?;
                return Ok(());
            }
        });
    }

    if value.is_none() {
        ctx.say("No value or long_value found. Use 'none' if you wish to unset a field")
            .await?;
        return Ok(());
    }

    let value = value.unwrap();

    let guild = ctx.guild().unwrap();

    // Vaildate the guild

    if guild.explicit_content_filter != serenity::model::guild::ExplicitContentFilter::All {
        ctx.say("You must have a explicit content filter set to scan messages from all users in your servers settings! See https://lynx.fateslist.xyz/privacy#server-listing").await?;
        return deny_server(data, guild.id.0 as i64).await;
    } else if !guild.features.contains(&"COMMUNITY".to_string()) {
        ctx.say("Your server must be a community server in order to be listed. See https://lynx.fateslist.xyz/privacy#server-listing").await?;
        return deny_server(data, guild.id.0 as i64).await;
    }

    let member = ctx.author_member().await;

    if member.is_none() {
        ctx.say("You must be in a server to use this command")
            .await?;
        return Ok(());
    }

    let member = member.unwrap();

    // Check if user has logged in or not
    let check = sqlx::query!(
        "SELECT user_id FROM users WHERE user_id = $1",
        member.user.id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if check.is_err() {
        sqlx::query!(
            "INSERT INTO users (id, user_id, username, api_token) VALUES ($1, $1, $2, $3)",
            member.user.id.0 as i64,
            member.user.name,
            create_token(128)
        )
        .execute(&data.pool)
        .await?;
    }

    let mut value = value; // Force it to be mutable and shadow immutable value

    if value == *"none" {
        value = "".to_string();
    }

    // Update server details
    let guild_with_mc = ctx.discord().http.get_guild_with_counts(guild.id.0).await?;

    let member_count = guild_with_mc
        .approximate_member_count
        .unwrap_or(guild.member_count);

    sqlx::query!(
        "INSERT INTO servers (guild_id, owner_id, name_cached, avatar_cached, api_token, guild_count) VALUES ($1, $2, $3, $4, $5, $6) 
        ON CONFLICT (guild_id) DO UPDATE SET owner_id = excluded.owner_id, name_cached = excluded.name_cached, 
        avatar_cached = excluded.avatar_cached, guild_count = excluded.guild_count WHERE 
        servers.guild_id = $1",
        guild.id.0 as i64,
        ctx.author().id.0 as i64,
        guild.name.to_string(),
        guild.icon_url().unwrap_or_else(|| "https://api.fateslist.xyz/static/botlisticon.webp".to_string()),
        create_token(128),
        member_count as i64,
    )
    .execute(&data.pool)
    .await?;

    sqlx::query!(
        "UPDATE servers SET flags = array_remove(flags, $1) WHERE guild_id = $2",
        Flags::NSFW as i32,
        guild.id.0 as i64,
    )
    .execute(&data.pool)
    .await?;

    if guild.nsfw_level == serenity::NsfwLevel::Explicit
        || guild.nsfw_level == serenity::NsfwLevel::AgeRestricted
    {
        sqlx::query!(
            "UPDATE servers SET flags = array_append(flags, $1) WHERE guild_id = $2",
            Flags::NSFW as i32,
            guild.id.0 as i64,
        )
        .execute(&data.pool)
        .await?;
    }

    let state = sqlx::query!(
        "SELECT state, flags, extra_links FROM servers WHERE guild_id = $1",
        guild.id.0 as i64
    )
    .fetch_one(&data.pool)
    .await?;

    if state.state == (State::Banned as i32) {
        ctx.say(
            "
**Your server has been banned due to breaking our rules. 

Please contact Fates List Staff if you wish to appeal. 
        
Note that ``/set`` and other commands will still work to allow you to make any required changes**",
        )
        .await?;
    } else if state.state == (State::Denied as i32) {
        enable_server(data, guild.id.0 as i64).await?;
    }

    // Force HTTP(s)
    value = value.replace("http://", "https://");

    match field {
        SetField::Description => {
            if value.len() > 200 {
                ctx.say("Description must be less than 200 characters")
                    .await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET description = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::LongDescription => {
            if value.len() < 200 {
                ctx.say("Long description must be at least 200 characters.\n\nThis is required in order to create a optimal user experience for your users!\n\n!").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET long_description = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::LongDescriptionType => {
            let long_desc_type = match value.as_str() {
                "html" | "0" => LongDescriptionType::Html,
                "markdown" | "1" => LongDescriptionType::MarkdownServerSide,
                _ => {
                    ctx.say(
                        "Long description type must be either `html` (`0`) or `markdown` (`1`)",
                    )
                    .await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET long_description_type = $1 WHERE guild_id = $2",
                long_desc_type as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::InviteCode => {
            if value == *"" {
                let none: Option<String> = None;
                sqlx::query!(
                    "UPDATE servers SET invite_url = $1 WHERE guild_id = $2",
                    none,
                    guild.id.0 as i64
                )
                .execute(&data.pool)
                .await?;
            } else {
                // Check for MANAGE_GUILD
                let bot = ctx.discord().cache.current_user();
                let bot_member = guild.member(&ctx.discord(), bot.id).await?;
                if !bot_member.permissions(&ctx.discord())?.manage_guild() {
                    ctx.say("The bot must have the `Manage Server` permission to change invite codes.
    This is due to a discord API limitation to lock required invite information behind the Manage Server permission.
                    
    It is strongly recommended to remove this permission **immediately** after setting invite code for security purposes"
                ).await?;
                    return Ok(());
                }

                // Validate invite code
                let guild_invites = guild.invites(&ctx.discord()).await?;

                value = value
                    .replace("https://discord.gg/", "")
                    .replace("https://discord.com/invite/", "");

                let mut got_invite: Option<serenity::RichInvite> = None;
                for invite in guild_invites {
                    if invite.code == value {
                        got_invite = Some(invite);
                        break;
                    }
                }

                if got_invite.is_none() {
                    ctx.say("Invite code could not be found on this guild")
                        .await?;
                    return Ok(());
                }

                let got_invite = got_invite.unwrap();

                if got_invite.max_age != 0 {
                    ctx.say("Invite code must be permanent/unlimited time. 
                    
    This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                    return Ok(());
                }

                if got_invite.max_uses != 0 {
                    ctx.say("Invite code must be unlimited use. 
                    
    This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                    return Ok(());
                }

                if got_invite.temporary {
                    ctx.say("Invite code must not be temporary. 
                    
    This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                    return Ok(());
                }

                sqlx::query!(
                    "UPDATE servers SET invite_url = $1 WHERE guild_id = $2",
                    got_invite.code,
                    guild.id.0 as i64
                )
                .execute(&data.pool)
                .await?;
            }
        }
        SetField::InviteChannelID => {
            // Check for CREATE_INVITES
            let value: String = value.chars().filter(|c| c.is_digit(10)).collect();

            let value_i64 = value.parse::<i64>()?;

            let bot = ctx.discord().cache.current_user();

            let mut got_channel: Option<serenity::GuildChannel> = None;

            for channel in guild.channels(&ctx.discord()).await? {
                if channel.0 .0 == value_i64 as u64 {
                    got_channel = Some(channel.1);
                }
            }

            if got_channel.is_none() {
                ctx.say("Channel could not be found on this guild").await?;
                return Ok(());
            }

            let got_channel = got_channel.unwrap();

            if !got_channel
                .permissions_for_user(&ctx.discord(), bot.id)?
                .create_instant_invite()
            {
                ctx.say("The bot must have the `Create Instant Invite` permission to set invite channel.").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET invite_channel = $1 WHERE guild_id = $2",
                value_i64,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::Website => {
            if !value.starts_with("https://") && value != *"" {
                ctx.say("Website must start with https://").await?;
                return Ok(());
            }

            let mut extra_links = state.extra_links.clone();

            let extra_links = extra_links.as_object_mut().unwrap();

            if extra_links.contains_key("Website") {
                extra_links.remove("Website");
            } else if extra_links.contains_key("website") {
                extra_links.remove("website");
            }

            if value != *"" {
                extra_links.insert("website".to_string(), json!(&value));
            }

            sqlx::query!(
                "UPDATE servers SET extra_links = $1 WHERE guild_id = $2",
                json!(extra_links),
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::Css => {
            sqlx::query!(
                "UPDATE servers SET css = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::BannerCard => {
            ctx.defer().await?;
            helpers::check_banner_img(&data.client, &value).await?;

            sqlx::query!(
                "UPDATE servers SET banner_card = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::BannerPage => {
            ctx.defer().await?;
            helpers::check_banner_img(&data.client, &value).await?;

            sqlx::query!(
                "UPDATE servers SET banner_page = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::KeepBannerDecor => {
            let keep_banner_decor = match value.as_str() {
                "true" | "0" => true,
                "false" | "1" => false,
                _ => {
                    ctx.say("keep_banner_decor must be either `false` (`0`) or `true` (`1`)")
                        .await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET flags = array_remove(flags, $1) WHERE guild_id = $2",
                Flags::KeepBannerDecor as i32,
                guild.id.0 as i64,
            )
            .execute(&data.pool)
            .await?;

            if keep_banner_decor {
                sqlx::query!(
                    "UPDATE servers SET flags = array_append(flags, $1) WHERE guild_id = $2",
                    Flags::KeepBannerDecor as i32,
                    guild.id.0 as i64,
                )
                .execute(&data.pool)
                .await?;
            }
        }
        SetField::Vanity => {
            let check = sqlx::query!(
                "SELECT type, redirect FROM vanity WHERE lower(vanity_url) = $1",
                value.to_lowercase()
            )
            .fetch_one(&data.pool)
            .await;

            match check {
                Err(sqlx::Error::RowNotFound) => {
                    // Remove old vanity
                    sqlx::query!("DELETE FROM vanity WHERE redirect = $1", guild.id.0 as i64)
                        .execute(&data.pool)
                        .await?;

                    // Add new vanity
                    sqlx::query!(
                        "INSERT INTO vanity (type, vanity_url, redirect) VALUES ($1, $2, $3)",
                        0,
                        value,
                        ctx.guild().unwrap().id.0 as i64
                    )
                    .execute(&data.pool)
                    .await?;
                }
                Err(e) => {
                    return Err(Box::new(e));
                }
                Ok(row) => {
                    ctx.say(format!(
                        "Vanity URL is already in use by `{:?}` of ID `{:?}`",
                        row.r#type, row.redirect
                    ))
                    .await?;
                    return Ok(());
                }
            }
        }
        SetField::State => {
            let state = match value.as_str() {
                "public" | "approved" | "0" => State::Approved,
                "private_viewable" | "8" => State::PrivateViewable,
                _ => {
                    ctx.say("State must be either `public`/`approved` (`0`) or `private_viewable` (`8`)").await?;
                    return Ok(());
                }
            };

            let check = sqlx::query!(
                "SELECT state FROM servers WHERE guild_id = $1",
                ctx.guild().unwrap().id.0 as i64
            )
            .fetch_one(&data.pool)
            .await?;

            if check.state != (State::Approved as i32)
                && check.state != (State::PrivateViewable as i32)
            {
                ctx.say("You cannot perform this action at this time. Is your bot flagged, denied, banned, certified or pending review?") .await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET state = $1 WHERE guild_id = $2",
                state as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::WebhookURL => {
            if !value.starts_with("https://") && value != *"" {
                ctx.say("Webhook URL must start with https://").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET webhook = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::WebhookType => {
            let webhook_type = match value.as_str() {
                "vote" | "0" => WebhookType::Vote,
                "discord" | "1" => WebhookType::DiscordIntegration,
                _ => {
                    ctx.say("Webhook type must be either `vote` (`0`) or `discord` (`1`)")
                        .await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET webhook_type = $1 WHERE guild_id = $2",
                webhook_type as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::WebhookSecret => {
            sqlx::query!(
                "UPDATE servers SET webhook_secret = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            // Remove value for audit logs
            value = "redacted for security reasons".to_string();

            // Prevent others from seeing interaction
            ctx.defer_ephemeral().await?;
        }
        SetField::WebhookHMACOnly => {
            let webhook_hmac_only = match value.as_str() {
                "true" | "0" => true,
                "false" | "1" => false,
                _ => {
                    ctx.say("webhook_hmac_only must be either `false` (`0`) or `true` (`1`)")
                        .await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET webhook_hmac_only = $1 WHERE guild_id = $2",
                webhook_hmac_only,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::RequiresLogin => {
            let requires_login = match value.as_str() {
                "true" | "0" => true,
                "false" | "1" => false,
                _ => {
                    ctx.say("requires_login must be either `false` (`0`) or `true` (`1`)")
                        .await?;
                    return Ok(());
                }
            };

            // Remove from flags first to remove duplicates

            sqlx::query!(
                "UPDATE servers SET flags = array_remove(flags, $1) WHERE guild_id = $2",
                Flags::LoginRequired as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            if requires_login {
                sqlx::query!(
                    "UPDATE servers SET flags = array_append(flags, $1) WHERE guild_id = $2",
                    Flags::LoginRequired as i32,
                    ctx.guild().unwrap().id.0 as i64
                )
                .execute(&data.pool)
                .await?;
            }
        }
        SetField::VoteRoles => {
            let mut vote_roles = Vec::new();
            value = value.replace(',', "|");
            for role_id in value.split('|') {
                let role_id = role_id.trim();
                if role_id.is_empty() {
                    continue;
                }

                let role_id = role_id.parse::<i64>()?;

                let role = guild.roles.get(&serenity::RoleId(role_id as u64));
                if let Some(role) = role {
                    vote_roles.push(role.id.0 as i64);
                } else {
                    ctx.say(format!(
                        "Ignoring role: {:?} as it could not be found",
                        role_id
                    ))
                    .await?;
                }
            }

            if vote_roles.len() > 3 {
                ctx.say("You can only have up to 3 vote roles").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET autorole_votes = $1 WHERE guild_id = $2",
                &vote_roles,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
        SetField::WhitelistOnly => {
            let whitelist_only = match value.as_str() {
                "true" | "0" => true,
                "false" | "1" => false,
                _ => {
                    ctx.say("whitelist_only must be either `false` (`0`) or `true` (`1`)")
                        .await?;
                    return Ok(());
                }
            };

            // Remove from flags first to remove duplicates

            sqlx::query!(
                "UPDATE servers SET flags = array_remove(flags, $1) WHERE guild_id = $2",
                Flags::WhitelistOnly as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            if whitelist_only {
                sqlx::query!(
                    "UPDATE servers SET flags = array_append(flags, $1) WHERE guild_id = $2",
                    Flags::WhitelistOnly as i32,
                    ctx.guild().unwrap().id.0 as i64
                )
                .execute(&data.pool)
                .await?;
            }
        }
        SetField::WhitelistForm => {
            if !value.starts_with("https://") && value != *"" {
                ctx.say("Whitelist Form must start with https://").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET whitelist_form = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        }
    }

    // Audit log entry
    sqlx::query!(
        "INSERT INTO server_audit_logs (guild_id, user_id, username, user_guild_perms, field, value) VALUES ($1, $2, $3, $4, $5, $6)",
        guild.id.0 as i64,
        ctx.author().id.0 as i64,
        ctx.author().name,
        member.permissions(&ctx.discord()).unwrap().bits().to_string(),
        format!("{:?}", field),
        value
    )
    .execute(&data.pool)
    .await?;

    ctx.say(format!("Set {:?} successfully. Either use /dumpserver or check out your server page!\n\nIf you wish to delete your server from server listing at any time, use `/delserver`. Fates List is not responsible for any harm caused by using Fates List Server Listing. *Please read our server listing rules available at https://lynx.fateslist.xyz/privacy#server-listing to ensure everyone has a good experience*\n\nYour servers name and icon has also been updated on the site", field)).await?;

    Ok(())
}
