use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
    Nonce
};

use rand::RngCore;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

// Password entry stored in the vault.
#[derive(Serialize, Deserialize, Debug)] 
struct Entry { 
    name: String, 
    username: String, 
    password: String, 
}

// The vault
#[derive(Serialize, Deserialize, Debug, Default)] 
struct Vault {
    entries: Vec<Entry>, 
}

// Putting the encrypted vault in a file.
// Storing it as .pass_vault
fn vault_path() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| ".".into());
    dir.push(".pass_vault");
    dir
}

// Converts the master password into 32-byte key using the SHA-256 (look cargo.toml)
// Want to try and use something stronger
fn pass_to_key(master: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Encrypting using AES-256-GCM
// It will random generate 12-byte
fn encrypt(vault: &Vault, key: &[u8;32]) -> Vec<u8> {
    
    // creating the cipher instance
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    // Random generator
    let mut nonce_byte = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_byte); 
    let nonce = Nonce::from_slice(&nonce_byte);

    // Putting it in a JSON file 
    let plaintext = serde_json::to_vec(vault).unwrap();

    // Encrypt JSON 
    let mut ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    // Prepend nonce so we can decrypt later 
    let mut out = nonce_byte.to_vec(); 
    out.append(&mut ciphertext); 
    out
}


// Decrypt the vault using AES‑256‑GCM. 
fn decrypt_vault(data: &[u8], key: &[u8; 32]) -> Option<Vault> { 
    if data.len() < 12 { 
        return None; 
    } 
    
    let (nonce_bytes, ciphertext) = data.split_at(12); 
    
    let cipher = Aes256Gcm::new_from_slice(key).ok()?; 
    
    let nonce = Nonce::from_slice(nonce_bytes); 
    
    // Attempt decryption 
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?; 
    
    // Deserialize 
    serde_json::from_slice(&plaintext).ok() 
} 

// Load vault from disk, decrypting it.
fn load_vault(key: &[u8; 32]) -> Vault { 
    let path = vault_path(); 
    if !path.exists() { 
        return Vault::default(); 
    } 
    
    let data = fs::read(path).expect("failed to read vault file"); 
    decrypt_vault(&data, key).unwrap_or_default() 
} 
    
// Encrypt 
fn save_vault(vault: &Vault, key: &[u8; 32]) { 
    let data = encrypt(vault, key); 
    fs::write(vault_path(), data).expect("failed to write vault file"); 
}


// Listing the entries.
fn listing_entries(vault: &Vault) {
    if vault.entries.is_empty() {
        println!("There is nothing!");
        return;
    }

    for (i, entry) in vault.entries.iter().enumerate(){
        println!("{}. {} ({})", i + 1, entry.name, entry.username)
    }
}


// Searching
fn searching(vault: &Vault, query: &str) {
    let query = query.to_lowercase();
    let mut found = false;

    // It will go through every entry and find the name
    for entry in &vault.entries{
        if entry.name.to_lowercase().contains(&query) || entry.username.to_lowercase().contains(&query){
            println!("Found: {} ({})\nPassword: {}", entry.name, entry.username, entry.password);
            found = true;
        }
    }

    if !found{
        println!("No match!")
    }
}


// Main function for everything.
fn main() {
    let path = vault_path();
    let first_time = !path.exists();

    // If there is non then a master password will be created.
    let master = if first_time {
        println!("No vault found. Creating a new one.");
        println!("Create a master password:");
        let p1 = read_password().expect("failed to read password");

        println!("Confirm master password:");
        let p2 = read_password().expect("failed to read password");

        // Needs to make sure the passwords match.
        if p1 != p2 {
            println!("Passwords do not match. Exiting.");
            return;
        }

        // Create an empty vault encrypted with this new key
        let key = pass_to_key(&p1);
        let empty = Vault::default();
        save_vault(&empty, &key);

        println!("Vault created.");
        p1
    } else {
        println!("Enter master password:");
        read_password().expect("failed to read password")
    };

    let key = pass_to_key(&master);

    println!("Password manager ready.");

    // Going through the menu
    loop {

        println!("Password Manager Menu:");
        println!("1. Add Entry");
        println!("2. List Entries");
        println!("3. Search");
        println!("4. Quit");

        // Getting the choice the use requested.
        let mut choice = String::new(); 
        std::io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                println!("Entry name:"); 
                let mut name = String::new(); 
                std::io::stdin().read_line(&mut name).unwrap(); 
                let name = name.trim().to_string();

                println!("Username:");
                let mut username = String::new();
                std::io::stdin().read_line(&mut username).unwrap();
                let username = username.trim().to_string();


                // ADD PASSWORD CONFERMATION
                let password = loop {
                    println!("Password (will not echo):");
                    let password1 = read_password().expect("Failed");

                    println!("Confirm your password: ");
                    let password2 = read_password().expect("Failed");

                    if password1 == password2 {
                        break password1;
                    }else{
                        println!("Password did not match try again!!!")
                    }
                };

                let mut vault = load_vault(&key);
                vault.entries.push(Entry { name, username, password });
                save_vault(&vault, &key);

                println!("Entry added.");
            }

            // Loading all the entries.
            "2" => {
                let vault = load_vault(&key);
                listing_entries(&vault);
            }

            // User can search by website or name.
            "3" => {
                println!("Search by Username or Name: ");
                let mut query = String::new();
                std::io::stdin().read_line(&mut query).unwrap();
                let query = query.trim();

                let vault = load_vault(&key);
                searching(&vault, query);
            }

            "4" => {
                println!("Goodbye! Have a fantastic day!");
                break;
            }

            _ => {
                println!("Invalid!!!!")
            }
        }
    }
}
