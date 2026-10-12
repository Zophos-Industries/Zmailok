mod agent;
mod agent_log;
mod api;
mod browser;
mod check;
mod login;
mod monitor;
mod store;
mod update;

use std::net::Ipv4Addr;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use colored::Colorize;
use zmailok::types::CheckOptions;

#[derive(Parser)]
#[command(name = "zmailok", version, about = "Email deliverability checker. One command, one score, one fix list.", disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a domain's email setup. Runs on your machine: free, unlimited, no account.
    Check {
        /// Domain to check, e.g. example.com
        domain: String,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
        /// Your mail server's IPv4 address, for the PTR, rDNS and blacklist checks (default: the domain's A record, skipped if the domain sends through Google, SendGrid and the like)
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// A DKIM selector to try first (selectors are arbitrary, so the built-in list can miss yours)
        #[arg(long)]
        dkim_selector: Option<String>,
    },
    /// Log in with GitHub (needed for hosted monitoring)
    Login,
    /// Log out and delete the saved login
    Logout,
    /// Hosted monitoring: checks your domains every 6 hours and emails you when the score drops
    Monitor {
        #[command(subcommand)]
        action: MonitorAction,
    },
    /// Subscribe to hosted monitoring ($5/month, up to 5 domains)
    Upgrade,
    /// Run as a daemon on your own mail server: watches its IP, bounces, complaints and score
    Agent {
        /// Settings file (YAML)
        #[arg(long, default_value = "agent.yaml")]
        config: std::path::PathBuf,
        /// Run one check and exit (0 = OK, 1 = needs attention)
        #[arg(long)]
        once: bool,
    },
    /// Update zmailok to the newest version on crates.io (reinstalls with cargo)
    Update,
    /// Show every command with a short description
    Help,
}

#[derive(Subcommand)]
enum MonitorAction {
    /// List the monitored domains and their latest scores
    List,
    /// Start monitoring a domain
    Add { domain: String },
    /// Stop monitoring a domain
    Remove { domain: String },
    /// Check a monitored domain right now instead of waiting for the next 6-hourly check (once a minute per domain)
    Check { domain: String },
}

/// Every command and subcommand, with its one-line description, indented by depth.
fn list_commands(cmd: &clap::Command, depth: usize, out: &mut String) {
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
        out.push_str(&format!("{:indent$}{:<10}{about}\n", "", sub.get_name(), indent = 2 + depth * 2));
        list_commands(sub, depth + 1, out);
    }
}

fn print_all_commands() {
    let cmd = Cli::command();
    println!("{} — every command\n", "zmailok".bold());
    println!("Usage: zmailok <COMMAND>\n\nCommands:");
    let mut out = String::new();
    list_commands(&cmd, 0, &mut out);
    print!("{out}");
    println!("\nRun 'zmailok <COMMAND> --help' for the options of one command.");
}

#[tokio::main]
async fn main() -> ExitCode {
    let matches = match Cli::command().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            if matches!(e.kind(), clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand) {
                print_all_commands(); // bare "zmailok": show the list
                return ExitCode::SUCCESS;
            }
            if !e.use_stderr() {
                e.print().ok(); // --help / --version
                return ExitCode::SUCCESS;
            }
            // Unknown or incomplete command: name the problem, then show every command.
            let problem = e.render().to_string();
            eprintln!("{}", problem.lines().next().unwrap_or("error: invalid input").replace("error: ", &format!("{} ", "error:".red().bold())));
            eprintln!();
            print_all_commands();
            return ExitCode::from(2);
        }
    };
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    if matches!(cli.command, Command::Help) {
        print_all_commands();
        return ExitCode::SUCCESS;
    }
    match run(cli.command).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e:#}", "error:".red().bold());
            ExitCode::from(2) // 1 is reserved for "the score did not pass"
        }
    }
}

async fn run(command: Command) -> anyhow::Result<ExitCode> {
    let api = || api::Api::new(store::load()?);
    match command {
        Command::Check { domain, json, ip, dkim_selector } => {
            return check::run(&domain, CheckOptions { ip, dkim_selector }, json).await;
        }
        Command::Login => login::run(&api()?).await?,
        Command::Logout => {
            let api = api()?;
            // a failed revoke (offline, session already gone) must not stop the local logout
            if let Err(e) = api.logout().await {
                eprintln!("{} could not tell the service ({e}); removing the saved login anyway", "note:".yellow());
            }
            store::delete()?;
            println!("{} Logged out.", "✓".green());
        }
        Command::Monitor { action } => match action {
            MonitorAction::List => monitor::list(&api()?).await?,
            MonitorAction::Add { domain } => monitor::add(&api()?, &domain).await?,
            MonitorAction::Remove { domain } => monitor::remove(&api()?, &domain).await?,
            MonitorAction::Check { domain } => {
                let passed = monitor::check(&api()?, &domain).await?;
                return Ok(if passed { ExitCode::SUCCESS } else { ExitCode::from(1) });
            }
        },
        Command::Upgrade => monitor::upgrade(&api()?).await?,
        Command::Help => {}
        Command::Update => update::run().await?,
        Command::Agent { config, once } => {
            let ok = agent::run(&config, once).await?;
            return Ok(if ok { ExitCode::SUCCESS } else { ExitCode::from(1) });
        }
    }
    Ok(ExitCode::SUCCESS)
}
