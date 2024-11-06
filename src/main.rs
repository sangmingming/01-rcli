use std::fs;

use clap::Parser;
use rcli::{
    process_csv, process_decode, process_decrypt, process_encode, process_encrypt,
    process_generate_key, process_genpass, process_text_sign, process_text_verify,
    Base64SubCommand, TextSignFormat, TextSubCommand,
};
use rcli::{Opts, SubCommand};
use zxcvbn::zxcvbn;

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output_path: String = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output_path, opts.format)?;
        }
        SubCommand::GenPass(opts) => {
            let pass = process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbol,
            )?;
            println!("{}", pass);
            let estimate: zxcvbn::Entropy = zxcvbn(&pass, &[]);
            eprintln!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(subcmd) => match subcmd {
            Base64SubCommand::Encode(opts) => {
                let encoded = process_encode(&opts.input, opts.format)?;
                println!("{}", encoded);
            }
            Base64SubCommand::Decode(opts) => {
                let decoded = process_decode(&opts.input, opts.format)?;
                println!("{}", decoded);
            }
        },
        SubCommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opts) => {
                let signed = process_text_sign(&opts.input, &opts.key, opts.format)?;
                println!("{}", signed);
            }
            TextSubCommand::Verify(opts) => {
                let verify_result =
                    process_text_verify(&opts.input, &opts.key, opts.format, &opts.sig)?;
                println!("Verify Result {}", verify_result);
            }
            TextSubCommand::Generate(opts) => {
                let key = process_generate_key(opts.format)?;
                match opts.format {
                    TextSignFormat::Blake3 => {
                        let path = opts.output.join("blake3.key");
                        fs::write(path, &key[0])?;
                    }
                    TextSignFormat::Ed25519 => {
                        let pri_path = opts.output.join("ed25519.key");
                        let pub_path = opts.output.join("ed25519.pub");
                        fs::write(pri_path, &key[0])?;
                        fs::write(pub_path, &key[1])?;
                    }
                }
            }
            TextSubCommand::Encrypt(opts) => {
                let result = process_encrypt(&opts.input, &opts.key)?;
                println!("encrypted content is: {}", result);
            }
            TextSubCommand::Decrypt(opts) => {
                let result = process_decrypt(&opts.input, &opts.key)?;
                println!("the origin content is: {}", result);
            }
        },
    }
    anyhow::Ok(())
}
