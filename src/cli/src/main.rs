mod args;
mod commands;
mod exit;
mod prompt;

use args::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::WARN
        })
        .without_time()
        .init();

    match commands::run(cli.command) {
        Ok(()) => std::process::exit(exit::OK),
        Err(failure) => {
            eprintln!("certsign: {}", failure.message);
            std::process::exit(failure.code);
        }
    }
}
