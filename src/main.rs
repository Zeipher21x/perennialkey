use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    sync::atomic::{AtomicUsize, Ordering},
};

use sha1::Sha1;
use hex;
use rayon::prelude::*;

const SHA1_HEX_STRING_LENGTH: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.len() > 4 {
        println!("Usage:");
        println!("sha1_cracker: <wordlist.txt> <sha1_hash> [-t]");
        return Ok(());
    }

    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != SHA1_HEX_STRING_LENGTH {
        return Err("sha1 hash is not valid".into());
    }

    let should_show_tries = args.iter().any(|arg| arg == "-t");

    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(wordlist_file);

    let tries = AtomicUsize::new(0);

    let found_password = reader
        .lines()
        .par_bridge()
        .find_any(|line| {
            let common_password = line.as_deref().unwrap_or_default().trim();
            let mut hasher = Sha1::new();
            hasher.update(common_password.as_bytes());
            let hashed_password = hasher.digest().bytes();

            let current_try = tries.fetch_add(1, Ordering::SeqCst) + 1;

            if should_show_tries {
                println!("Try #{}: Password: {}, Hash: {:?}", current_try, common_password, hashed_password);
            }

            let hashed_password_hex = hex::encode(hashed_password);
            hash_to_crack == hashed_password_hex
        });

    if let Some(line) = found_password {
        println!("Password found: {}", line.unwrap());
    } else {
        println!("Password not found in wordlist after {} tries :(", tries.load(Ordering::Relaxed));
    }

    Ok(())
}
