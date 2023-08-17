use lair_keystore_api::ipc_keystore_connect;
use tokio::runtime::Runtime;
use url::Url;
use std::fs;
use toml;
use dirs::home_dir;
use serde::Deserialize;
use serde_yaml;

#[derive(Deserialize)]
struct LairConfig {
    connectionUrl: String,
}

#[derive(Deserialize)]
struct Config {
    passphrase: String,
}

fn main() {
    // Create a Tokio runtime to run async code
    let rt = Runtime::new().unwrap();
    rt.block_on(async_main());
}

async fn async_main() {
    let connectionUrl = read_lair_config().expect("Failed to read the lair configuration");
    let passphrase = read_config().expect("Failed to read the configuration");

    let passphrase_bytes = passphrase.into_bytes();

    // Connect to the keystore
    let client = ipc_keystore_connect(Url::parse(&connectionUrl).unwrap(), passphrase_bytes.clone()).await.expect("Failed to connect to Lair Keystore");

    println!("Successfully connected to Lair Keystore!");

    let seed_tag = "unique-test-seed-5"; // Change this to a unique tag
    match client.new_seed(seed_tag.into(), None, false).await {
        Ok(seed_info) => {
            println!("Seed with tag '{}' has been successfully created!", seed_tag);

            // Sign some data
            let message = b"test-data";
            let sig = client.sign_by_pub_key(seed_info.ed25519_pub_key.clone(), None, message.to_vec().into()).await.expect("Failed to sign data");

            println!("Data has been successfully signed with signature: {:?}", sig);

            // Verify the signature
            assert!(seed_info.ed25519_pub_key.verify_detached(sig, message.to_vec()).await.expect("Failed to verify signature"));
        },
        Err(err) => {
            eprintln!("Error creating new seed: {:?}", err);
        }
    }
}

fn read_lair_config() -> Result<String, Box<dyn std::error::Error>> {
    let home_directory = home_dir().expect("Unable to determine home directory");
    let config_path = home_directory.join("holochain-keystore/lair-keystore-config.yaml");
    let content = fs::read_to_string(config_path)?;
    let config: LairConfig = serde_yaml::from_str(&content)?;
    Ok(config.connectionUrl)
}

fn read_config() -> Result<String, Box<dyn std::error::Error>> {
    let home_directory = home_dir().expect("Unable to determine home directory");
    let config_path = home_directory.join("holochain-keystore/config.toml");
    let content = fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config.passphrase)
}
