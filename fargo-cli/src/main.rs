#![deny(warnings)]

use {
    anyhow::Result,
    rand::Rng,
    std::{
        fs::File,
        io::{Read, Write},
        path::{Path, PathBuf},
        str,
    },
    structopt::StructOpt,
};

#[derive(StructOpt, Debug)]
#[structopt(name = "fargo-cli", about = "Encryption/decryption tool")]
enum Command {
    /// Encrypt a file
    Encrypt {
        /// File to encrypt
        input_file: PathBuf,

        /// Output file to which to write encrypted data
        output_file: PathBuf,
    },

    /// Decrypt a file
    Decrypt {
        /// File to decrypt
        input_file: PathBuf,

        /// Output file to which to write decrypted data
        output_file: PathBuf,
    },
}

fn read(file: &Path) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    File::open(file)?.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn write(data: &[u8], file: &Path) -> Result<()> {
    File::create(file)?.write_all(data)?;

    Ok(())
}

fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    let command = Command::from_args();

    let password = rpassword::read_password_from_tty(Some("password: "))?;

    match command {
        Command::Encrypt {
            input_file,
            output_file,
        } => {
            let mut nonce = [0u8; fargo::NONCE_SIZE];

            rand::thread_rng().fill(&mut nonce);

            write(
                &fargo::encrypt(nonce, str::from_utf8(&read(&input_file)?)?, &password)?,
                &output_file,
            )?;
        }

        Command::Decrypt {
            input_file,
            output_file,
        } => {
            write(
                fargo::decrypt(&read(&input_file)?, &password)?.as_bytes(),
                &output_file,
            )?;
        }
    }

    Ok(())
}
