mod base64;
mod csv;
mod genpass;
mod http;
mod text;

use crate::CmdExector;

pub use self::base64::{Base64Format, Base64SubCommand};
pub use self::csv::{CsvOpts, OutputFormat};
pub use self::http::HttpSubCommand;
pub use self::text::{TextSignFormat, TextSubCommand};
use clap::Parser;
use genpass::GenPassOpts;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert csv to other format")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand, about = "Base64 encode/decode")]
    Base64(Base64SubCommand),
    #[command(subcommand, about = "Text sign/verify/encrypt")]
    Text(TextSubCommand),
    #[command(subcommand, about = "HTTP File Server")]
    Http(HttpSubCommand),
}

impl CmdExector for SubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Self::Csv(opts) => opts.execute().await,
            Self::Base64(opts) => opts.execute().await,
            Self::GenPass(opts) => opts.execute().await,
            Self::Http(cmd) => cmd.execute().await,
            Self::Text(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(p.into())
    } else {
        Err("Dir dif not exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("no-exist"), Err("File does not exist"));
    }
}
