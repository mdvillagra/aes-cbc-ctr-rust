use aes::cipher::typenum::U16;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use hex::FromHex;
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

    let a_bytes = hex::decode(a).unwrap();
    let b_bytes = hex::decode(b).unwrap();

    let xor = a_bytes
        .iter()
        .zip(b_bytes.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>();

    xor.iter().fold("".to_string(), |acc, n| {
        format!("{acc}{}", hex::encode(vec![*n]))
    })
}
/// CBC mode with AES128
fn cbc_aes128_encrypt(m: String, k: String) -> String {
    assert_eq!(k.len(), 32, "the lentgh of the key must be 32");
    assert_eq!(m.len() % 2, 0, "the message length is not even");

    // padding PKCS5
    let padded_message = pkcs5(m);

    // initialize cipher
    let key = GenericArray::from(<[u8; 16]>::from_hex(k).unwrap());
    let cipher = Aes128::new(&key);

    // generate random IV
    let mut rng = rand::thread_rng();
    let random_bytes = vec![0; 16]
        .iter()
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>();
    let random_iv = hex::encode(random_bytes);

    // string for the ciphertext
    let mut c = Vec::<String>::new();

    // push the IV as the first element in the ciphertext
    c.push(random_iv.clone());

    // encrypt each block
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

// adds 1 to the IV
fn add_one_iv(iv: String) -> String {
    let mut bits = iv
        .chars()
        .map(|i| if i == '1' { 1 } else { 0 })
        .collect::<Vec<u8>>();

    let n = bits.len();
    bits[n - 1] += 1;
    let mut carry = if bits[n - 1] > 1 { 1 } else { 0 };
    for i in (0..n - 1).rev() {
        bits[i] += carry;
        carry = if bits[i] > 1 { 1 } else { 0 };
        bits[i] %= 2;
    }

    bits.iter()
        .map(|i| if *i == 1 { '1' } else { '0' })
        .collect::<String>()
}

/// CTR mode with AES128
fn ctr_aes128(m: String, k: String) -> String {
    assert_eq!(k.len(), 32, "the lentgh of the key must be 32");
    assert_eq!(m.len() % 2, 0, "the message length is not even");

    // padding PKCS5
    let padded_message = pkcs5(m);

    // initialize cipher
    let key = GenericArray::from(<[u8; 16]>::from_hex(k).unwrap());
    let cipher = Aes128::new(&key);

    // generate random IV of bits
    let mut rng = rand::thread_rng();
    let random_bytes = vec![0; 16]
        .iter()
        .map(|_| rng.gen::<bool>())
        .collect::<Vec<bool>>();
    let random_iv = random_bytes.iter().fold("".to_string(), |acc, n| {
        format!("{acc}{}", hex::encode(vec![if *n { 1 } else { 0 }]))
    });

    // string for the ciphertext
    let mut c = Vec::<String>::new();

    // push the IV as the first element in the ciphertext
    c.push(random_iv.clone());

    // encrypt each block
    for i in 0..padded_message.len() / 32 {
        let next_iv = random_iv
            .chars()
            .map(|i| if i == '1' { 1 } else { 0 })
            .collect::<Vec<u8>>();
        let a: GenericArray<u8, U16> = GenericArray::clone_from_slice(&next_iv);
        let block_xor = xor_16bytes_hex(
            c[c.len() - 1].clone(),
            padded_message[i * 32..i * 32 + 32].to_string(),
        );
        let mut block_xor_bytes = GenericArray::from(
            <[u8; 16]>::from_hex(padded_message[i * 32..i * 32 + 32].to_string()).unwrap(),
        );
        cipher.encrypt_block(&mut block_xor_bytes);
        c.push(hex::encode(block_xor_bytes.to_vec()));
    }

    c.iter().fold("".to_string(), |acc, x| format!("{acc}{x}"))
}

fn main() {
    let c1 = String::from("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
    let key1 = String::from("140b41b22a29beb4061bda66b6747e14");

    println!("{}", cbc_aes128_encrypt(c1, key1));
}
