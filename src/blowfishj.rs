use crate::cts::BlowfishCTS;
use hex;
use std::error::Error;

pub fn encrypt(key: &str, src: &str) -> Result<String, Box<dyn Error>> {
    let buf = src.as_bytes().to_vec();
    let mut encrypted_buf = buf.clone();
    let mut cts = BlowfishCTS::new();
    cts.initialize(key.as_bytes())?;
    cts.encrypt(&buf, 0, &mut encrypted_buf, 0, buf.len());
    Ok(hex::encode_upper(encrypted_buf))
}

pub fn decrypt(key: &str, src: &str) -> Result<String, Box<dyn Error>> {
    let buf = hex::decode(src)?;
    let mut decrypted_buf = buf.clone();
    let mut cts = BlowfishCTS::new();
    cts.initialize(key.as_bytes())?;
    cts.decrypt(&buf, 0, &mut decrypted_buf, 0, buf.len());
    Ok(String::from_utf8(decrypted_buf)?)
}

#[cfg(test)]
mod tests {
    use super::*; // Bring your encrypt and decrypt functions into scope

    struct Fixture {
        secret: &'static str,
        text: &'static str,
        encrypted: &'static str,
    }

    const FIXTURES: &[Fixture] = &[
        Fixture {
            secret: "foobar",
            text: "How I wish I could recollect PI easily using one trick?",
            encrypted: "5D09840C5A0E7A196D949FC41012E27913C5E752AF38136C5ABDD2603B7F2A92198983B6DB7098C063E08D0AECA2891423FBAE3DE636A2",
        },
        Fixture {
            secret: "密碼",
            text: "一二三四 one two 3 4",
            encrypted: "4EF013DD039DDE30EAF13E04E17F21039C77760C3DADE16C",
        },
    ];

    #[test]
    fn test_encrypt() {
        for fixture in FIXTURES {
            let got = encrypt(fixture.secret, fixture.text).expect("encrypt failed");
            assert_eq!(
                got, fixture.encrypted,
                "Invalid encrypted text for secret: {}",
                fixture.secret
            );
        }
    }

    #[test]
    fn test_decrypt() {
        for fixture in FIXTURES {
            let got = decrypt(fixture.secret, fixture.encrypted).expect("decrypt failed");
            assert_eq!(
                got, fixture.text,
                "Invalid decrypted text for secret: {}",
                fixture.secret
            );
        }
    }
}
