mod cli;
mod process;
mod utils;

pub use cli::*;
use enum_dispatch::enum_dispatch;

pub use process::{
    process_csv, process_decode, process_decrypt, process_encode, process_encrypt,
    process_generate_key, process_genpass, process_http_serve, process_text_sign,
    process_text_verify,
};

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait CmdExector {
    async fn execute(self) -> anyhow::Result<()>;
}
