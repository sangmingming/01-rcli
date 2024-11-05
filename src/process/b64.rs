use crate::Base64Format;
use anyhow::Error;
use base64::{
    engine::general_purpose::GeneralPurpose, engine::general_purpose::STANDARD,
    engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use std::{fs::File, io::Read};

pub fn process_encode(input: &str, format: Base64Format) -> anyhow::Result<()> {
    let buff = read_buff(input)?;
    let encoded = create_engine(format).encode(buff);
    println!("{}", encoded);
    anyhow::Ok(())
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<()> {
    let buff = read_buff(input)?;
    let buff = buff.trim_ascii_end();
    let decoded = create_engine(format).decode(buff)?;
    let decoded = String::from_utf8(decoded)?;
    println!("{}", decoded);
    anyhow::Ok(())
}

fn read_buff(input: &str) -> Result<Vec<u8>, Error> {
    let mut reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

fn create_engine(format: Base64Format) -> GeneralPurpose {
    match format {
        Base64Format::Standard => STANDARD,
        Base64Format::UrlSafe => URL_SAFE_NO_PAD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_process_decode() {
        let input = "fixtures/b64.txt";
        let format = Base64Format::Standard;
        assert!(process_decode(input, format).is_ok());
    }

    #[test]
    fn test_process_encode() {
        let input = "fixtures/b64-input.txt";
        let format = Base64Format::Standard;
        assert!(process_encode(input, format).is_ok());
    }
}
