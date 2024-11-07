mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;

pub use self::base64::*;
pub use self::csv::*;
pub use self::genpass::*;
pub use self::http::*;
pub use self::jwt::*;
pub use self::text::*;
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
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
    #[command(subcommand, about = "Jwt token sign/verify")]
    Jwt(JwtSubCommand),
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
