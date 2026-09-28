use arch_program::pubkey::Pubkey;

use bitcoin::{
    address::Address,
    key::{Parity, UntweakedKeypair},
    secp256k1::{Secp256k1, SecretKey},
    XOnlyPublicKey,
};
use rand_core::OsRng;

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    str::FromStr,
};

/// Generates an untweaked keypair, and provides it's pubkey and BTC address
/// corresponding to the currently used BTC Network
pub fn generate_new_keypair(network: bitcoin::Network) -> (UntweakedKeypair, Pubkey, Address) {
    let secp = Secp256k1::new();

    let (secret_key, _public_key) = secp.generate_keypair(&mut OsRng);

    let key_pair = UntweakedKeypair::from_secret_key(&secp, &secret_key);

    let (x_only_public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let address = Address::p2tr(&secp, x_only_public_key, None, network);

    let pubkey = Pubkey::from_slice(&XOnlyPublicKey::from_keypair(&key_pair).0.serialize());

    (key_pair, pubkey, address)
}

pub fn with_secret_key_file(file_path: &str) -> Result<(UntweakedKeypair, Pubkey), std::io::Error> {
    let secp = Secp256k1::new();

    let file_content = fs::read_to_string(file_path);

    let secret_key = match file_content {
        Ok(key) => {
            if let Ok(sk) = SecretKey::from_str(&key) {
                sk
            } else {
                let secret_bytes: Vec<u8> = serde_json::from_str(&key).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "File content is neither a valid secret key string nor a serialized vector of bytes",
                    )
                })?;
                if secret_bytes.len() < 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Secret key byte vector too short: expected at least 32 bytes, got {}",
                            secret_bytes.len()
                        ),
                    ));
                }
                SecretKey::from_slice(&secret_bytes[0..32]).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to parse secret key from bytes",
                    )
                })?
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let (key, _) = secp.generate_keypair(&mut OsRng);
            write_new_secret_key(file_path, &key)?;
            key
        }
        Err(err) => {
            return Err(err);
        }
    };
    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let pubkey = Pubkey::from_slice(&XOnlyPublicKey::from_keypair(&keypair).0.serialize());

    Ok((keypair, pubkey))
}

/// Writes the secret key to a new file, readable only by the owner on Unix.
/// Fails with `AlreadyExists` rather than overwrite a file created concurrently.
fn write_new_secret_key(file_path: &str, secret_key: &SecretKey) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(file_path)?;
    let result = file
        .write_all(secret_key.display_secret().to_string().as_bytes())
        .and_then(|_| file.sync_all());
    if let Err(err) = result {
        // Don't leave a truncated or unsynced key behind for the next load to fail on.
        drop(file);
        let _ = fs::remove_file(file_path);
        return Err(err);
    }
    Ok(())
}

pub fn is_parity_even(key_pair: &UntweakedKeypair) -> bool {
    key_pair.x_only_public_key().1 == Parity::Even
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_file_is_generated_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let path = path.to_str().unwrap();

        let (_, generated) = with_secret_key_file(path).unwrap();
        let (_, reloaded) = with_secret_key_file(path).unwrap();

        assert_eq!(generated, reloaded);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        with_secret_key_file(path.to_str().unwrap()).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn existing_file_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        fs::write(&path, "created concurrently").unwrap();

        let (secret_key, _) = Secp256k1::new().generate_keypair(&mut OsRng);
        let err = write_new_secret_key(path.to_str().unwrap(), &secret_key).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), "created concurrently");
    }
}
