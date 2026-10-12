mod api;
mod browser;
mod check;
mod login;
mod monitor;
mod store;

use std::net::Ipv4Addr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use colored::Colorize;
use zmailok::types::CheckOptions;

#[derive(Parser)]
#[command(name = "zmailok", version, about = "Email deliverability checker. One command, one score, one fix list.")]
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
}

#[derive(Subcommand)]
enum MonitorAction {
    /// List the monitored domains and their latest scores
    List,
    /// Start monitoring a domain
    Add { domain: String },
    /// Stop monitoring a domain
    Remove { domain: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
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
        },
        Command::Upgrade => monitor::upgrade(&api()?).await?,
    }
    Ok(ExitCode::SUCCESS)
}
