use rand::seq::SliceRandom;
use zxcvbn::zxcvbn;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBER: &[u8] = b"1234567890";
const SYMBOL: &[u8] = b"!@#$%^&*_-";

pub fn process_genpass(
    length: u8,
    uppercase: bool,
    lowercase: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<()> {
    let mut password = String::new();
    let mut chars = Vec::new();
    if uppercase {
        chars.extend_from_slice(UPPER);
    }
    if lowercase {
        chars.extend_from_slice(LOWER);
    }
    if number {
        chars.extend_from_slice(NUMBER);
    }
    if symbol {
        chars.extend_from_slice(SYMBOL);
    }
    let mut rng = rand::thread_rng();
    for _ in 0..length {
        let c = chars
            .choose(&mut rng)
            .expect("chars won't be  empty in this context");
        password.push(*c as char);
    }
    println!("{}", password);
    let estimate = zxcvbn(&password, &[]);
    eprintln!("Password strength: {}", estimate.score());
    anyhow::Ok(())
}
