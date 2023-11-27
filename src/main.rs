use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use hex::{FromHex, ToHex};
use rand::Rng;

/// PKCS5 padding of message m
fn pkcs5(m: String) -> String {
    assert_eq!(m.len() % 2, 0, "the message length is not even");

    let padded_message: String;

    if m.len() % 32 == 0 {
        let padd_hex = String::from("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        padded_message = format!("{m}{padd_hex}");
    } else {
        let mut count: u32 = 0;
        while m.len() != 0 {
            count += 1;
        }
        count /= 2;
        let padd_hex = hex::encode(count.to_string());
        padded_message = format!("{m}{padd_hex}");
    }
    padded_message
}

/// Returns the xor of a and b in hex
fn xor_16bytes_hex(a: String, b: String) -> String {
    assert_eq!(a.len(), 32, "a must be 16 bytes long");
    assert_eq!(b.len(), 32, "b must be 16 bytes long");

    a.chars()
        .zip(b.chars())
        .map(|(x, y)| x as u8 ^ y as u8)
        .map(|u| hex::encode(u.to_string()))
        .fold("".to_string(), |acc, n| format!("{acc}{n}"))
}
/// CBC mode with AES128
fn cbc_aes128(m: String, k: String) -> String {
    assert_eq!(k.len(), 32, "the lentgh of the key must be 32");
    assert_eq!(m.len() % 2, 0, "the message length is not even");

    // padding PKCS5
    let padded_message = pkcs5(m);

    // initialize cipher
    let key = GenericArray::from(<[u8; 16]>::from_hex(k).unwrap());
    let cipher = Aes128::new(&key);

    // generate random IV
    let mut rng = rand::thread_rng();
    let random_iv = hex::encode([
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
    ]);

    // string for the ciphertext
    let mut c = Vec::<String>::new();

    // push the IV as the first element in the ciphertext
    c.push(random_iv.clone());

    for i in 0..padded_message.len() / 32 {
        let block_xor = xor_16bytes_hex(
            c[c.len() - 1].clone(),
            padded_message[i * 32..i * 32 + 32].to_string(),
        );
        let mut block_xor_bytes = GenericArray::from(<[u8; 16]>::from_hex(block_xor).unwrap());
        cipher.encrypt_block(&mut block_xor_bytes);
        c.push(hex::encode(block_xor_bytes.to_vec()));
    }

    c.iter().fold("".to_string(), |acc, x| format!("{acc}{x}"))
}

fn main() {
    let c1 = String::from("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");

    println!("{}", c1.len());
}
