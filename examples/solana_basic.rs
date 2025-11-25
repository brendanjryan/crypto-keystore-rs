use crypto_keystore_rs::{ChainKey, SolanaKeystore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    println!("Creating new Solana keystore...");

    let keystore = SolanaKeystore::new(password)?;
    let address = keystore.key()?.public_key();

    println!("Generated Solana address: {address}");
    println!("Keystore version: {}", keystore.version());
    println!("Chain: {:?}", keystore.chain());

    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore to: ./keystores/{uuid}.json");

    println!("Loading keystore from file...");
    let loaded = SolanaKeystore::load_from_file(format!("./keystores/{uuid}.json"), password)?;

    println!("Loaded address: {}", loaded.key()?.public_key());

    assert_eq!(loaded.key()?.public_key(), address);
    println!("Address matches after load");

    Ok(())
}
