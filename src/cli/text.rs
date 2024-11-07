use crate::{
    process_decrypt, process_encrypt, process_generate_key, process_text_sign, process_text_verify,
    CmdExector,
};

use super::{verify_file, verify_path};
use anyhow::Error;
use clap::Parser;
use core::fmt;
use enum_dispatch::enum_dispatch;
use std::{fs, path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum TextSubCommand {
    #[command(about = "Sign a message with a private/shared key")]
    Sign(TextSignOpts),
    #[command(about = "Verify a signed message")]
    Verify(TextVerifyOpts),
    #[command(about = "Generate a key for message sign and verify")]
    Generate(TextGenerateKeyOpts),
    #[command(about = "Encrypt message")]
    Encrypt(TextEncryptOpts),
    #[command(about = "Decrypt message")]
    Decrypt(TextDecryptOpts),
}

impl CmdExector for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let result = process_encrypt(&self.input, &self.key)?;
        println!("encrypted content is: {}", result);
        Ok(())
    }
}

impl CmdExector for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let result = process_decrypt(&self.input, &self.key)?;
        println!("the origin content is: {}", result);
        Ok(())
    }
}

impl CmdExector for TextGenerateKeyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process_generate_key(self.format)?;
        match self.format {
            TextSignFormat::Blake3 => {
                let path = self.output.join("blake3.key");
                fs::write(path, &key[0])?;
            }
            TextSignFormat::Ed25519 => {
                let pri_path = self.output.join("ed25519.key");
                let pub_path = self.output.join("ed25519.pub");
                fs::write(pri_path, &key[0])?;
                fs::write(pub_path, &key[1])?;
            }
        }
        Ok(())
    }
}

impl CmdExector for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verify_result = process_text_verify(&self.input, &self.key, self.format, &self.sig)?;
        println!("Verify Result {}", verify_result);
        Ok(())
    }
}

impl CmdExector for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let signed = process_text_sign(&self.input, &self.key, self.format)?;
        println!("{}", signed);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct TextGenerateKeyOpts {
    #[arg(long, default_value="blake3", value_parser = parse_format)]
    pub format: TextSignFormat,
    #[arg(short, long, default_value = "fixtures", value_parser = verify_path)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, default_value="blake3", value_parser = parse_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(short, long)]
    pub sig: String,
    #[arg(long, default_value="blake3", value_parser = parse_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

impl FromStr for TextSignFormat {
    type Err = Error;

    #[allow(unreachable_code)]
    fn from_str(format: &str) -> Result<Self, Self::Err> {
        match format.to_lowercase().as_str() {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::bail!("Unsupported format type {}", format)),
        }
    }
}

impl From<TextSignFormat> for &'static str {
    fn from(format: TextSignFormat) -> Self {
        match format {
            TextSignFormat::Blake3 => "blake3",
            TextSignFormat::Ed25519 => "ed25519",
        }
    }
}

fn parse_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}
