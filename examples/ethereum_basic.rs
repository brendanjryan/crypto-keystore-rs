use crypto_keystore_rs::{ChainKey, EthereumKeystore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    println!("Creating new Ethereum keystore...");

    let keystore = EthereumKeystore::new(password)?;
    let address = keystore.key()?.public_key();

    println!("Generated Ethereum address: {address}");
    println!("Keystore version: {}", keystore.version());
    println!("Chain: {:?}", keystore.chain());

    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore to: ./keystores/{uuid}.json");

    println!("Loading keystore from file...");
    let loaded = EthereumKeystore::load_from_file(format!("./keystores/{uuid}.json"), password)?;

    println!("Loaded address: {}", loaded.key()?.public_key());

    assert_eq!(loaded.key()?.public_key(), address);
    println!("Address matches after load");

    Ok(())
}
