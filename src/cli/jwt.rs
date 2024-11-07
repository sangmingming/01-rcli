use clap::Parser;
use enum_dispatch::enum_dispatch;

use crate::{
    process::{process_jwt_generate, process_jwt_verify},
    CmdExector,
};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(name = "sign", about = "jwt sign")]
    Sign(JwtSignOpts),
    #[command(about = "jwt verify")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long)]
    pub sub: String,
    #[arg(short, long)]
    pub aud: String,
    #[arg(short, long, default_value_t = 100)]
    pub exp: u64,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
    #[arg(short, long)]
    pub aud: String,
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token: String = process_jwt_generate(self.sub, self.aud, self.exp)?;
        println!("the generate jwt is: {}", token);
        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verify_result = process_jwt_verify(self.token, self.aud)?;
        println!("verify result: {}", verify_result);
        Ok(())
    }
}
