#![feature(async_closure)]

use poise::serenity_prelude as serenity;
use log::{debug, info, error};
use std::fs::File;
use std::io::Read;
use std::env;
use std::path::PathBuf;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
struct Data {pool: sqlx::PgPool, client: reqwest::Client}
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
        ctx.say(format!("**Error:** {}", json["reason"].as_str().unwrap_or("Unknown error"))).await?;
    }

    Ok(())
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
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// Register application commands in this guild or globally
///
/// Run with no arguments to register in guild, run with argument "global" to register globally.
#[poise::command(prefix_command, hide_in_help)]
async fn register(ctx: Context<'_>, #[flag] global: bool) -> Result<(), Error> {
    poise::builtins::register_application_commands(ctx, global).await?;

    Ok(())
}

// Internal Secrets Struct
#[derive(Deserialize)]
pub struct Secrets {
    pub token_squirrelflight: String,
}

fn get_bot_token() -> String {
    let path = match env::var_os("HOME") {
        None => { panic!("$HOME not set"); }
        Some(path) => PathBuf::from(path),
    };    

    let data_dir = path.into_os_string().into_string().unwrap() + "/FatesList/config/data/";

    debug!("Data dir: {}", data_dir);

    // open secrets.json, handle config
    let mut file = File::open(data_dir + "secrets.json").expect("No config file found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let secrets: Secrets = serde_json::from_str(&data).expect("JSON was not well-formatted");

    secrets.token_squirrelflight
}

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    // This is our custom error handler
    // They are many errors that can occur, so we only handle the ones we want to customize
    // and forward the rest to the default handler
    match error {
        poise::FrameworkError::Setup { error } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx } => {
            error!("Error in command `{}`: {:?}", ctx.command().name, error,);
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                error!("Error while handling error: {}", e)
            }
        }
    }
}

async fn event_listener(
    _ctx: &serenity::Context,
    event: &poise::Event<'_>,
    _framework: &poise::Framework<Data, Error>,
    user_data: &Data,
) -> Result<(), Error> {
    match event {
        poise::Event::Ready { data_about_bot } => {
            info!("{} is connected!", data_about_bot.user.name)
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
                                msg_inter.create_interaction_response(_ctx.http.clone(), |m| {
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
                                        msg_inter.create_interaction_response(_ctx.http.clone(), |m| {
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
                                msg_inter.create_interaction_response(_ctx.http.clone(), |m| {
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
                                msg_inter.create_interaction_response(_ctx.http.clone(), |m| {
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

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "squirrelflight=debug");
    env_logger::init();
    info!("Starting Squirrelfight...");

    const MAX_CONNECTIONS: u32 = 3; // max connections to the database, we don't need too many here

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
                client,
            })
        }))
        .options(poise::FrameworkOptions {
            // configure framework here
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("+".into()),
                ..Default::default()
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
            commands: vec![accage(), vote(), help(), register()],
            ..Default::default()
        })
        .run().await.unwrap();
}
