mod cli;
mod process;

pub use cli::{Opts, SubCommand};
pub use process::process_csv;
pub use process::process_genpass;
