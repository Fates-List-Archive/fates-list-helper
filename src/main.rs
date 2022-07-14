use bigdecimal::BigDecimal;
use bigdecimal::FromPrimitive;
use bigdecimal::ToPrimitive;
use bristlefrost::models::{State, TargetType};
use deadpool::Runtime;
use log::{debug, error, info};
use poise::serenity_prelude as serenity;
use poise::serenity_prelude::Mentionable;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::{task, time};
pub struct Data {
    pool: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    client: reqwest::Client,
    key_data: KeyData,
}

#[derive(Serialize)]
struct NotificationSubData {
    endpoint: String,
    p256dh: String,
    auth: String,
    data: String,
}

#[derive(Serialize)]
struct Notification {
    users: Vec<String>,
    target_type: TargetType
}


type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

mod helpers;
mod serverlist;
mod staff;

/// Display your or another user's account creation date. Is a test command
#[poise::command(prefix_command, slash_command)]
async fn accage(
    ctx: Context<'_>,
    #[description = "Selected user"] user: Option<serenity::User>,
) -> Result<(), Error> {
    let user = user.as_ref().unwrap_or_else(|| ctx.author());
    ctx.say(format!(
        "{}'s account was created at {}",
        user.name,
        user.created_at()
    ))
    .await?;

    Ok(())
}

/// Votes for current server
#[poise::command(slash_command, guild_only)]
async fn voteserver(ctx: Context<'_>) -> Result<(), Error> {
    let data = ctx.data();
    let guild = ctx.guild().unwrap();

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

    let req = data
        .client
        .patch(format!(
            "https://api.fateslist.xyz/users/{}/servers/{}/votes?test=false",
            ctx.author().id,
            guild.id
        ))
        .header("Authorization", token)
        .send()
        .await;

    if req.is_err() {
        ctx.say("Failed to vote for the server. Please try again later.")
            .await?;
        return Ok(());
    }

    let resp = req.unwrap();

    let status = resp.status();

    let json = resp.json::<serde_json::Value>().await?;

    if status == reqwest::StatusCode::OK {
        ctx.send(|m| {
            m.content(format!("You have successfully voted for {}", guild.name))
                .components(|c| {
                    c.create_action_row(|ar| {
                        ar.create_button(|b| {
                            b.style(serenity::ButtonStyle::Primary)
                                .label("Toggle Vote Reminders!")
                                .custom_id(format!(
                                    "vrtoggle-{}-{}-servers",
                                    ctx.author().id,
                                    guild.id
                                ))
                        })
                    })
                })
        })
        .await?;
    } else {
        ctx.send(|m| {
            m.content(format!(
                "**Error when voting for {}:** {}",
                guild.name,
                json["reason"].as_str().unwrap_or("Unknown error")
            ))
            .components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}-servers", ctx.author().id, guild.id))
                    })
                })
            })
        })
        .await?;
    }

    Ok(())
}

/// Votes for a bot. Takes a bot as its only parameter
#[poise::command(slash_command, prefix_command, track_edits)]
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

    let req = data
        .client
        .patch(format!(
            "https://api.fateslist.xyz/users/{}/bots/{}/votes?test=false",
            ctx.author().id,
            bot.id
        ))
        .header("Authorization", token)
        .send()
        .await;

    if req.is_err() {
        ctx.say("Failed to vote for the bot. Please try again later.")
            .await?;
        return Ok(());
    }

    let resp = req.unwrap();

    let status = resp.status();

    let json = resp.json::<serde_json::Value>().await?;

    if status == reqwest::StatusCode::OK {
        ctx.send(|m| {
            m.content(format!("You have successfully voted for {}", bot.name))
                .components(|c| {
                    c.create_action_row(|ar| {
                        ar.create_button(|b| {
                            b.style(serenity::ButtonStyle::Primary)
                                .label("Toggle Vote Reminders!")
                                .custom_id(format!("vrtoggle-{}-{}-bots", ctx.author().id, bot.id))
                        })
                    })
                })
        })
        .await?;
    } else {
        ctx.send(|m| {
            m.content(format!(
                "**Error when voting for {}:** {}",
                bot.name,
                json["reason"].as_str().unwrap_or("Unknown error").to_owned() + "\n**Context: **" + json["context"].as_str().unwrap_or("No additional information")
            ))
            .components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}-bots", ctx.author().id, bot.id))
                    })
                })
            })
        })
        .await?;
    }

    Ok(())
}

async fn autocomplete_vr_bot(
    ctx: Context<'_>,
    _partial: String,
) -> Vec<poise::AutocompleteChoice<String>> {
    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT vote_reminders FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if row.is_err() {
        return Vec::new();
    }

    let row = row.unwrap();

    let mut choices = Vec::new();
    for choice in row.vote_reminders {
        choices.push(poise::AutocompleteChoice {
            name: choice.to_string(),
            value: choice.to_string(),
        });
    }

    choices
}

async fn autocomplete_vr_server(
    ctx: Context<'_>,
    _partial: String,
) -> Vec<poise::AutocompleteChoice<String>> {
    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if row.is_err() {
        return Vec::new();
    }

    let row = row.unwrap();

    let mut choices = Vec::new();
    for choice in row.vote_reminders_servers {
        choices.push(poise::AutocompleteChoice {
            name: choice.to_string(),
            value: choice.to_string(),
        });
    }

    choices
}

#[derive(poise::ChoiceParameter, PartialEq, Debug)]
enum BotServer {
    #[name = "bot"]
    Bot,
    #[name = "server"]
    Server,
}

/// Set the channel to send vote reminders to.
#[poise::command(track_edits, prefix_command, slash_command)]
async fn vrchannel(
    ctx: Context<'_>,
    #[description = "Channel to send vote reminders to"] channel: serenity::Channel,
    #[description = "Bot or server"] vr_type: BotServer,
) -> Result<(), Error> {
    match channel.clone() {
        serenity::Channel::Guild(guild_channel) => match guild_channel.kind {
            serenity::ChannelType::Voice
            | serenity::ChannelType::Stage
            | serenity::ChannelType::Category
            | serenity::ChannelType::Unknown => {
                ctx.say("You can only set vote reminder channel to a text channel!")
                    .await?;
                return Ok(());
            }
            _ => (),
        },
        serenity::Channel::Private(_) => (),
        _ => {
            ctx.say("You can only set vote reminders to a guild channel!")
                .await?;
            return Ok(());
        }
    }

    if vr_type == BotServer::Bot {
        sqlx::query!(
            "UPDATE users SET vote_reminder_channel = $1 WHERE user_id = $2",
            channel.id().0 as i64,
            ctx.author().id.0 as i64
        )
        .execute(&ctx.data().pool)
        .await?;
    } else {
        sqlx::query!(
            "UPDATE users SET vote_reminder_servers_channel = $1 WHERE user_id = $2",
            channel.id().0 as i64,
            ctx.author().id.0 as i64
        )
        .execute(&ctx.data().pool)
        .await?;
    }

    ctx.say(format!(
        "Vote reminders will now be sent to {}",
        channel.mention()
    ))
    .await?;

    Ok(())
}

/// Disablevr base command
#[poise::command(track_edits, prefix_command, slash_command)]
async fn disablevr(ctx: Context<'_>) -> Result<(), Error> {
    ctx.say("Available options are ``disablevr bot``, ``disablevr server``")
        .await?;
    Ok(())
}

/// Disable vote reminders for a bot
#[poise::command(track_edits, prefix_command, slash_command, rename = "bot")]
async fn disablevr_bot(
    ctx: Context<'_>,
    #[description = "Bot ID to disable vote reminders for"]
    #[autocomplete = "autocomplete_vr_bot"]
    bot_id: Option<String>,
) -> Result<(), Error> {
    let data = ctx.data();

    if bot_id.is_none() {
        let row = sqlx::query!(
            "SELECT vote_reminders FROM users WHERE user_id = $1",
            ctx.author().id.0 as i64
        )
        .fetch_one(&data.pool)
        .await;

        let mut text = "Vote reminders enabled: ".to_string();

        for choice in row.unwrap().vote_reminders {
            text += &(choice.to_string() + ", ");
        }

        ctx.say(text).await?;
    } else {
        let bot_id = bot_id.unwrap();

        let bot_id = bot_id.parse::<i64>();

        if bot_id.is_err() {
            ctx.say("Bot id must be a i64").await?;
            return Ok(());
        }

        let bot_id = bot_id.unwrap();

        sqlx::query!(
            "UPDATE users SET vote_reminders = array_remove(vote_reminders, $1) WHERE user_id = $2",
            bot_id,
            ctx.author().id.0 as i64
        )
        .execute(&data.pool)
        .await?;

        ctx.say(format!("Vote reminders disabled for {}", bot_id))
            .await?;
    }

    Ok(())
}

/// Disable vote reminders for a server
#[poise::command(track_edits, prefix_command, slash_command, rename = "server")]
async fn disablevr_server(
    ctx: Context<'_>,
    #[description = "Server ID to disable vote reminders for"]
    #[autocomplete = "autocomplete_vr_server"]
    server_id: Option<String>,
) -> Result<(), Error> {
    let data = ctx.data();

    if server_id.is_none() {
        let row = sqlx::query!(
            "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
            ctx.author().id.0 as i64
        )
        .fetch_one(&data.pool)
        .await;

        let mut text = "Vote reminders enabled: ".to_string();

        for choice in row.unwrap().vote_reminders_servers {
            text += &(choice.to_string() + ", ");
        }

        ctx.say(text).await?;
    } else {
        let server_id = server_id.unwrap();

        let server_id = server_id.parse::<i64>();

        if server_id.is_err() {
            ctx.say("Server id must be a i64").await?;
            return Ok(());
        }

        let server_id = server_id.unwrap();

        sqlx::query!(
            "UPDATE users SET vote_reminders_servers = array_remove(vote_reminders_servers, $1) WHERE user_id = $2",
            server_id,
            ctx.author().id.0 as i64
        )
        .execute(&data.pool)
        .await?;

        ctx.say(format!("Vote reminders disabled for {}", server_id))
            .await?;
    }

    Ok(())
}

/// Show this help menu
#[poise::command(track_edits, prefix_command, slash_command)]
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
Squirrelflight & Server Listing Help. Ask on our support server for more information\n",
            show_context_menu_commands: true,
            ..poise::builtins::HelpConfiguration::default()
        },
    )
    .await?;
    Ok(())
}

/// Returns version information
#[poise::command(slash_command)]
async fn version(ctx: Context<'_>) -> Result<(), Error> {
    let git_commit_hash = Command::new("git").args(["rev-parse", "HEAD"]).output();

    let hash = if git_commit_hash.is_err() {
        "Unknown".to_string()
    } else {
        String::from_utf8(git_commit_hash.unwrap().stdout)
            .unwrap_or_else(|_| "Unknown (utf8 parse failure)".to_string())
    };

    ctx.say(format!(
        "Squirrelflight v0.1.0\n\n**Commit Hash:** {}",
        hash
    ))
    .await?;
    Ok(())
}

/// See the bot queue.
#[poise::command(slash_command, track_edits, rename = "botqueue")]
async fn queue(ctx: Context<'_>) -> Result<(), Error> {
    let data = ctx.data();

    let rows = sqlx::query!(
        "SELECT username_cached, bot_id, description FROM bots WHERE state = 1 ORDER BY created_at ASC",
    )
    .fetch_all(&data.pool)
    .await;

    if rows.is_err() {
        ctx.say("There was an error fetching the queue. Please try again later.")
            .await?;
        return Ok(());
    }

    let rows = rows.unwrap();

    let mut desc =
        "*Does not take into account bots that are currently under review*\n".to_string();

    let mut i = 1;

    for row in rows {
        let mut name = row.username_cached;
        if name.is_empty() {
            name = "Username not cached".to_string();
        }

        desc += format!(
            "\n**{i}. {name}** - [View On Site](https://fateslist.xyz/bot/{invite})\n{desc}",
            i = i,
            name = name,
            invite = row.bot_id,
            desc = row.description
        )
        .as_str();

        i += 1;
    }

    desc += "\n\n**Note to staff: Always see site pages before approving or even testing a bot!**";

    ctx.send(|m| {
        m.embed(|e| {
            e.title("**Bot Queue**");
            e.description(desc)
        })
    })
    .await?;

    Ok(())
}

/// Register application commands in this guild or globally
///
/// Run with no arguments to register in guild, run with argument "global" to register globally.
#[poise::command(prefix_command, slash_command, owners_only, track_edits)]
async fn register(
    ctx: Context<'_>,
    #[flag]
    #[description = "Global or no global registration"]
    global: bool,
) -> Result<(), Error> {
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
        None => {
            panic!("$HOME not set");
        }
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
            ctx.say(format!(
                "There was an error running this command: {:?}",
                error
            ))
            .await
            .unwrap();
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
    user_data: &Data,
) -> Result<(), Error> {
    match event {
        poise::Event::GuildDelete {
            incomplete,
            full: _,
        } => {
            debug!("Left guild {:?}", incomplete.id);

            sqlx::query!(
                "UPDATE servers SET old_state = state, state = $1 WHERE guild_id = $2",
                State::Hidden as i32,
                incomplete.id.0 as i64
            )
            .execute(&user_data.pool)
            .await?;
        }

        poise::Event::GuildCreate { guild, is_new } => {
            if *is_new {
                return Ok(());
            }

            sqlx::query!("UPDATE servers SET name_cached = $1, state = old_state WHERE guild_id = $2 AND state = $3", 
                         guild.name, 
                         guild.id.0 as i64,
                         State::Hidden as i32
            )
                .execute(&user_data.pool)
                .await?;
        }

        poise::Event::Ready { data_about_bot } => {
            info!("{} is connected!", data_about_bot.user.name);

            let _ctx = ctx.to_owned();
            let pool = user_data.pool.clone();
            let key_data = user_data.key_data.clone();

            task::spawn(async move {
                vote_reminder_task(pool, key_data, _ctx.http, BotServer::Bot).await;
            });

            let _ctx = ctx.to_owned();
            let pool = user_data.pool.clone();
            let key_data = user_data.key_data.clone();

            task::spawn(async move {
                vote_reminder_task(pool, key_data, _ctx.http, BotServer::Server).await;
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
                    if parts.len() != 4 {
                        return Ok(());
                    }
                    let user_id = parts[1].parse::<i64>();
                    let id = parts[2].parse::<i64>();
                    let vr_type = parts[3].parse::<String>();

                    if user_id.is_ok() && id.is_ok() && vr_type.is_ok() {
                        let user_id = user_id.unwrap();
                        let id = id.unwrap();
                        let vr_type = vr_type.unwrap();

                        let author = msg_inter.user.id.0 as i64;

                        if user_id != author {
                            return Ok(());
                        }

                        // Check if they've signed up for VR already
                        if vr_type == "bots" {
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
                                        &vec![id]
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
                                }
                                None => {
                                    debug!("Choosing VR path RowUpdate");

                                    let row = row.unwrap();
                                    for bot in row.vote_reminders {
                                        if bot == id {
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
                                        &vec![id]
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
                                }
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
                        } else {
                            // Check if they've signed up for VR already
                            let row = sqlx::query!(
                                "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
                                user_id
                            )
                            .fetch_one(&user_data.pool)
                            .await;

                            match row.as_ref().err() {
                                Some(sqlx::Error::RowNotFound) => {
                                    debug!("Choosing VR path RowInsert");
                                    sqlx::query!(
                                        "INSERT INTO users (user_id, vote_reminders_servers) VALUES ($1, $2)",
                                        user_id,
                                        &vec![id]
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
                                }
                                None => {
                                    debug!("Choosing VR path RowUpdate");

                                    let row = row.unwrap();
                                    for server in row.vote_reminders_servers {
                                        if server == id {
                                            msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                                m.interaction_response_data(|m| {
                                                    m.content("You have already subscribed to vote reminders for this server!");
                                                    m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);
            
                                                    m
                                                })
                                            }).await?;
                                            return Ok(());
                                        }
                                    }

                                    sqlx::query!(
                                        "UPDATE users SET vote_reminders_servers = vote_reminders_servers || $2 WHERE user_id = $1",
                                        user_id,
                                        &vec![id]
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
                                }
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
        }
        _ => {}
    }

    Ok(())
}

async fn vote_reminder_task(
    pool: sqlx::PgPool,
    key_data: KeyData,
    http: Arc<serenity::http::Http>,
    vr_type: BotServer,
) {
    let mut interval = time::interval(Duration::from_millis(10000));

    // Lets create a new client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("VRTask/0.1")
        .build()
        .unwrap();

    loop {
        interval.tick().await;
        debug!("Called VRTask: {:?}", vr_type); // TODO: Remove this

        match vr_type {
            BotServer::Bot => {
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
                    let voted = sqlx::query!(
                        "SELECT extract(epoch from expires_on) AS expiry FROM user_vote_table WHERE user_id = $1",
                        row.user_id
                    )
                    .fetch_one(&pool)
                    .await;

                    let expiry = match voted {
                        Ok(voted) => voted.expiry.unwrap_or_default(),
                        Err(_) => BigDecimal::from_u64(0).unwrap_or_default(),
                    }
                    .to_u64()
                    .unwrap_or_default();

                    let now = chrono::Utc::now().timestamp() as u64;

                    if expiry > now {
                        continue;
                    }

                    let mut channel: serenity::model::id::ChannelId =
                        key_data.channels.vote_reminder_channel;
                    if row.vote_reminder_channel.is_some() {
                        channel = serenity::model::id::ChannelId(
                            row.vote_reminder_channel
                                .unwrap()
                                .try_into()
                                .unwrap_or(key_data.channels.vote_reminder_channel.0),
                        );
                    }

                    // The hard part, bot string creation and push notifications

                    let mut push_bots = Vec::new();

                    let mut bots_str: String = "".to_string();

                    // tlen contains the total length of the vote reminders
                    // If tlen is one and was always one then we don't need to add a comma
                    let tlen_initial = row.vote_reminders.len();
                    let mut tlen = row.vote_reminders.len();

                    for bot in &row.vote_reminders {
                        // First add it to bot vec for push notifications
                        push_bots.push(bot.to_string());

                        let mut mod_front = "";
                        if tlen_initial > 1 && tlen == 1 {
                            // We have more than one bot, but we're at the last one
                            mod_front = " and ";
                        } else if tlen_initial > 1 && tlen > 1 {
                            // We have more than one bot, and we're not at the last one
                            mod_front = ", ";
                        }

                        if tlen == tlen_initial {
                            // At first bot, do nothing with mod_front
                            mod_front = "";
                        }

                        bots_str += format!(
                            "{mod_front}<@{bot}> ({bot})",
                            bot = bot,
                            mod_front = mod_front
                        )
                        .as_str();

                        tlen -= 1;
                    }

                    // Spawn push notification
                    task::spawn(
                        send_push(row.user_id, pool.clone(), client.clone(), Notification {
                            target_type: TargetType::Bot,
                            users: push_bots,
                        })
                    );

                    // Now actually send the message
                    let res = channel
                        .send_message(http.clone(), |m| {
                            m.content(format!(
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
            BotServer::Server => {
                let rows = sqlx::query!(
                    "SELECT user_id, vote_reminders_servers, vote_reminder_servers_channel FROM users 
                    WHERE cardinality(vote_reminders_servers) > 0 
                    AND NOW() - vote_reminders_servers_last_acked > interval '4 hours'"
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
                    let voted = sqlx::query!(
                        "SELECT extract(epoch from expires_on) AS expiry FROM user_server_vote_table WHERE user_id = $1",
                        row.user_id
                    )
                    .fetch_one(&pool)
                    .await;

                    let expiry = match voted {
                        Ok(voted) => voted.expiry.unwrap_or_default(),
                        Err(_) => BigDecimal::from_u64(0).unwrap_or_default(),
                    }
                    .to_u64()
                    .unwrap_or_default();

                    let now = chrono::Utc::now().timestamp() as u64;

                    if expiry > now {
                        continue;
                    }

                    let mut channel: serenity::model::id::ChannelId =
                        key_data.channels.vote_reminder_channel;
                    if row.vote_reminder_servers_channel.is_some() {
                        channel = serenity::model::id::ChannelId(
                            row.vote_reminder_servers_channel
                                .unwrap()
                                .try_into()
                                .unwrap_or(key_data.channels.vote_reminder_channel.0),
                        );
                    }

                    // The hard part, server string creation and push notifications
                    let mut push_servers = Vec::new();

                    let mut servers_str: String = "".to_string();

                    // tlen contains the total length of the vote reminders
                    // If tlen is one and was always one then we don't need to add a comma
                    let tlen_initial = row.vote_reminders_servers.len();
                    let mut tlen = row.vote_reminders_servers.len();

                    for server in &row.vote_reminders_servers {
                        push_servers.push(server.to_string());

                        let mut mod_front = "";
                        if tlen_initial > 1 && tlen == 1 {
                            // We have more than one bot, but we're at the last one
                            mod_front = " and ";
                        } else if tlen_initial > 1 && tlen > 1 {
                            // We have more than one bot, and we're not at the last one
                            mod_front = ", ";
                        }

                        if tlen == tlen_initial {
                            // At first bot, do nothing with mod_front
                            mod_front = "";
                        }

                        let server_row = sqlx::query!(
                            "SELECT name_cached FROM servers WHERE guild_id = $1",
                            server
                        )
                        .fetch_one(&pool)
                        .await;

                        if server_row.is_err() {
                            error!("{}", server_row.err().unwrap());
                            continue;
                        }

                        let server_row = server_row.unwrap();

                        servers_str += format!(
                            "{mod_front}{server_name} ({server})",
                            server_name = server_row.name_cached,
                            server = server,
                            mod_front = mod_front
                        )
                        .as_str();

                        tlen -= 1;
                    }

                    // Spawn push notification
                    task::spawn(
                        send_push(row.user_id, pool.clone(), client.clone(), Notification {
                            target_type: TargetType::Server,
                            users: push_servers,
                        })
                    );                    

                    // Now actually send the message
                    let res = channel
                        .send_message(http.clone(), |m| {
                            m.content(format!(
                                "Hey {user}, you can vote for {servers} or did you forget?",
                                user = serenity::model::id::UserId(row.user_id as u64).mention(),
                                servers = servers_str
                            ));

                            m
                        })
                        .await;

                    if res.is_err() {
                        error!("Message send error: {}", res.err().unwrap());
                    }

                    debug!(
                        "User {} with servers {:?}",
                        row.user_id, row.vote_reminders_servers
                    );

                    // Reack
                    let reack = sqlx::query!(
                        "UPDATE users SET vote_reminders_servers_last_acked = NOW() WHERE user_id = $1",
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
    }
}

async fn send_push(id: i64, pool: sqlx::PgPool, client: reqwest::Client, notification: Notification) {
    let devices = sqlx::query!(
        "SELECT endpoint, p256dh, auth FROM push_notifications WHERE user_id = $1",
        id
    )
    .fetch_all(&pool)
    .await;

    if devices.is_err() {
        debug!("Failed to get devices for user {}", id);
        return;
    }

    let devices = devices.unwrap();

    for device in devices {
        // Call flamepaw
        let res = client.post("http://127.0.0.1:1292/flamepaw/_remind")
        .json(&NotificationSubData {
            endpoint: device.endpoint,
            p256dh: device.p256dh,
            auth: device.auth,
            data: serde_json::to_string(&notification).unwrap(),
        })
        .send()
        .await;

        if res.is_err() {
            error!("Failed to send test notification to user {}", id);
        }

        debug!("{}", res.unwrap().status());
    }
}

#[tokio::main]
async fn main() {
    const MAX_CONNECTIONS: u32 = 3; // max connections to the database, we don't need too many here

    std::env::set_var("RUST_LOG", "fateslisthelper=debug");
    env_logger::init();
    info!("Starting Squirrelfight...");

    let client = reqwest::Client::builder()
        .user_agent("FatesList-Squirrelflight/1.0 (internal microservice)")
        .build()
        .unwrap();

    poise::Framework::build()
        .token(get_bot_token())
        .user_data_setup(move |_ctx, _ready, _framework| {
            let cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1001/1");

            Box::pin(async move {
                Ok(Data {
                    pool: PgPoolOptions::new()
                        .max_connections(MAX_CONNECTIONS)
                        .connect("postgres://localhost/fateslist")
                        .await
                        .expect("Could not initialize connection"),
                    key_data: get_key_data(),
                    redis: cfg.create_pool(Some(Runtime::Tokio1)).unwrap(),
                    client,
                })
            })
        })
        .intents(
            serenity::GatewayIntents::GUILDS
                | serenity::GatewayIntents::GUILD_MESSAGES
                | serenity::GatewayIntents::DIRECT_MESSAGES,
        )
        .options(poise::FrameworkOptions {
            // configure framework here
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("+".into()),
                ..poise::PrefixFrameworkOptions::default()
            },
            /// This code is run before every command
            pre_command: |ctx| {
                Box::pin(async move {
                    info!(
                        "Executing command {} for user {} ({})...",
                        ctx.command().qualified_name,
                        ctx.author().name,
                        ctx.author().id
                    );
                })
            },
            /// This code is run after every command returns Ok
            post_command: |ctx| {
                Box::pin(async move {
                    info!(
                        "Done executing command {} for user {} ({})...",
                        ctx.command().qualified_name,
                        ctx.author().name,
                        ctx.author().id
                    );
                })
            },
            on_error: |error| Box::pin(on_error(error)),
            listener: |ctx, event, _framework, user_data| {
                Box::pin(event_listener(ctx, event, user_data))
            },
            commands: vec![
                accage(),
                vote(),
                voteserver(),
                help(),
                register(),
                version(),
                queue(),
                poise::Command {
                    subcommands: vec![
                        staff::claim(),
                        staff::unclaim(),
                        staff::requeue(),
                        staff::unverify(),
                        staff::approve(),
                        staff::deny(),
                        staff::ban(),
                        staff::unban(),
                        staff::denyserver(),
                        staff::banserver(),
                        staff::enableserver(),
                    ],
                    ..staff::staff()
                },
                poise::Command {
                    subcommands: vec![disablevr_bot(), disablevr_server()],
                    ..disablevr()
                },
                vrchannel(),
                serverlist::webset(),
                serverlist::set(),
                serverlist::dumpserver(),
                serverlist::auditlogs(),
                serverlist::allowlist(),
                serverlist::tags(),
                serverlist::delserver(),
            ],
            ..poise::FrameworkOptions::default()
        })
        .run()
        .await
        .unwrap();
}
