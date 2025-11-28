use crypto_keystore_rs::EthereumKeystore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "secure_password_123";

    println!("Creating new Ethereum keystore...");

    let keystore = EthereumKeystore::new(password)?;
    let address = keystore.key()?.address();

    println!("Generated Ethereum address: {address}");
    println!("Keystore version: {}", keystore.version());
    println!("Chain: {:?}", keystore.chain());

    let uuid = keystore.save_to_file("./keystores")?;
    println!("Saved keystore to: ./keystores/{uuid}.json");

    println!("Loading keystore from file...");
    let loaded = EthereumKeystore::load_from_file(format!("./keystores/{uuid}.json"), password)?;

    println!("Loaded address: {}", loaded.key()?.address());

    assert_eq!(loaded.key()?.address(), address);
    println!("Address matches after load");

    Ok(())
}
