/*
 * Copyright (c) 2017 René Richter,
 * Copyright (c) 2015-2017 Alex Maslakov, <http://gildedhonour.com>, <http://alexmaslakov.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For questions and comments about this product, please see the project page at:
 *
 * https://github.com/Richterrettich/rusty_jwt
 *
 * This was forked from
 * https://github.com/GildedHonour/frank_jwt
 *
 */

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate time;
extern crate openssl;
extern crate base64;


use std::collections::BTreeMap;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use openssl::ec::EcKey;

pub type Payload = BTreeMap<String, String>;

#[derive(Serialize, Deserialize)]
pub struct Header {
    alg: Algorithm,
    typ: String,
}

impl Header {
    pub fn new(alg: Algorithm) -> Header {
        Header {
            alg: alg,
            typ: String::from("JWT"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

impl Algorithm {
    fn get_hash(&self) -> MessageDigest {
        match *self {
            Algorithm::HS256 | Algorithm::RS256 | Algorithm::ES256 => MessageDigest::sha256(),
            Algorithm::HS384 | Algorithm::RS384 | Algorithm::ES384 => MessageDigest::sha384(),
            Algorithm::HS512 | Algorithm::RS512 | Algorithm::ES512 => MessageDigest::sha512(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    SignatureExpired,
    SignatureInvalid,
    JWTInvalid,
    IssuerInvalid,
    ExpirationInvalid,
    AudienceInvalid,
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::SignatureExpired => "signature expired",
            Error::SignatureInvalid => "signature invalid",
            Error::JWTInvalid => "jwt invalid",
            Error::IssuerInvalid => "invalid issuer",
            Error::ExpirationInvalid => "invalid expiration",
            Error::AudienceInvalid => "invalid audience",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::SignatureExpired => write!(f, "signature expired"),
            Error::SignatureInvalid => write!(f, "signature invalid"),
            Error::JWTInvalid => write!(f, "jwt invalid"),
            Error::IssuerInvalid => write!(f, "invalid issuer"),
            Error::ExpirationInvalid => write!(f, "invalid expiration"),
            Error::AudienceInvalid => write!(f, "invalid audience"),
        }
    }
}

pub fn encode<T: ?Sized + AsRef<[u8]>>(header: Header, key: &T, payload: Payload) -> String {
    let signing_input = get_signing_input(payload, &header.alg);
    let kr = key.as_ref();
    let pkey = match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => PKey::hmac(kr).unwrap(),
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => rsa_key(kr),
        Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => ec_key(kr),
    };
    let signature = sign_and_encode(&signing_input, pkey, header.alg.get_hash());
    format!("{}.{}", signing_input, signature)
}

pub fn decode<T, E>(
    encoded_token: E,
    key: &T,
    algorithm: Algorithm,
) -> Result<(Header, Payload), Error>
where
    T: ?Sized + AsRef<[u8]>,
    E: AsRef<str>,
{
    match decode_segments(encoded_token.as_ref()) {
        Some((header, payload, signature, signing_input)) => {
            if !verify_signature(algorithm, signing_input, &signature, key.as_ref()) {
                return Err(Error::SignatureInvalid);
            }
            Ok((header, payload))
        }

        None => Err(Error::JWTInvalid),
    }
}

static SEGMENTS_COUNT: usize = 3;



fn get_signing_input(payload: Payload, algorithm: &Algorithm) -> String {
    let header = Header::new(*algorithm);
    let header_json_str =
        serde_json::to_string(&header).expect("could not convert header to json.");
    let encoded_header = base64::encode_config(header_json_str.as_bytes(), base64::URL_SAFE_NO_PAD)
        .to_string();
    let payload_json = serde_json::to_string(&payload).expect("could not convert payload to json");
    let encoded_payload = base64::encode_config(payload_json.as_bytes(), base64::URL_SAFE_NO_PAD)
        .to_string();
    format!("{}.{}", encoded_header, encoded_payload)
}


fn rsa_key(raw_key: &[u8]) -> PKey {
    let rsa = Rsa::private_key_from_pem(raw_key).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn ec_key(raw_key: &[u8]) -> PKey {
    let ec_key =
        EcKey::private_key_from_pem(&raw_key).expect("could not convert to EC private key");
    PKey::from_ec_key(ec_key).expect("could not convert EC private key")
}

fn sign(data: &str, private_key: PKey, digest: MessageDigest) -> Vec<u8> {
    let mut signer = Signer::new(digest, &private_key).unwrap();
    signer.update(data.as_bytes()).unwrap();
    signer.finish().unwrap()
}

fn sign_and_encode(data: &str, private_key: PKey, digest: MessageDigest) -> String {
    let raw = sign(data, private_key, digest);
    base64::encode_config(&raw, base64::URL_SAFE_NO_PAD)
}


fn decode_segments(encoded_token: &str) -> Option<(Header, Payload, Vec<u8>, String)> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        return None;
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let crypto_segment = raw_segments[2];
    let (header, payload) = decode_header_and_payload(header_segment, payload_segment);
    let signature = base64::decode_config(crypto_segment, base64::URL_SAFE_NO_PAD)
        .expect("could not decoding base64 signature");
    let signing_input = format!("{}.{}", header_segment, payload_segment);
    Some((header, payload, signature.clone(), signing_input))
}



fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> (Header, Payload) {
    let headder_bytes = base64::decode(header_segment).expect("could not decoding base64 header");
    let header: Header =
        serde_json::from_slice(&headder_bytes[..]).expect("could not convert header to json");


    let payload_bytes = base64::decode(payload_segment).expect("could not decoding base64 payload");
    let payload: Payload =
        serde_json::from_slice(&payload_bytes[..]).expect("could not convert header to json");
    (header, payload)
}



fn verify_signature(
    algorithm: Algorithm,
    signing_input: String,
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    match algorithm {

        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let key = PKey::hmac(public_key).unwrap();
            let signature2 = sign(&signing_input, key, algorithm.get_hash());
            secure_compare(signature, &signature2)
        }
        _ => {
            let key = PKey::public_key_from_pem(public_key).expect("could not convert pem to pkey");
            let mut verifier = Verifier::new(algorithm.get_hash(), &key).unwrap();
            verifier.update(signing_input.as_bytes()).unwrap();
            verifier.finish(&signature).unwrap()
        }
    }
}

fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut res = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }

    res == 0
}

#[cfg(test)]
mod tests {
    extern crate time;

    use super::Header;
    use super::Payload;
    use super::encode;
    use super::decode;
    use super::Algorithm;
    use super::secure_compare;
    use std::env;

    #[test]
    fn test_encode_and_decode_jwt_hs256() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        p1.insert("key3".to_string(), "val3".to_string());

        let secret = "secret123";
        let header = Header::new(Algorithm::HS256);
        let jwt1 = encode(header, secret, p1.clone());
        let maybe_res = decode(jwt1.trim(), secret, Algorithm::HS256);
        assert!(maybe_res.is_ok());
    }

    static HS256_JWT: &'static str = include_str!("../test/valid_hs256.jwt");
    #[test]
    fn test_decode_valid_jwt_hs256() {
        let mut p1 = Payload::new();
        p1.insert("key11".to_string(), "val1".to_string());
        p1.insert("key22".to_string(), "val2".to_string());
        let secret = "secret123";
        let maybe_res = decode(HS256_JWT, secret, Algorithm::HS256);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_secure_compare_same_strings() {
        let str1 = "same same".as_bytes();
        let str2 = "same same".as_bytes();
        let res = secure_compare(str1, str2);
        assert!(res);
    }

    #[test]
    fn test_fails_when_secure_compare_different_strings() {
        let str1 = "same same".as_bytes();
        let str2 = "same same but different".as_bytes();
        let res = secure_compare(str1, str2);
        assert!(!res);
    }

    #[test]
    fn test_encode_and_decode_jwt_hs384() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        p1.insert("key3".to_string(), "val3".to_string());

        let secret = "secret123";
        let header = Header::new(Algorithm::HS384);
        let jwt1 = encode(header, secret, p1.clone());
        let maybe_res = decode(jwt1, secret, Algorithm::HS384);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encode_and_decode_jwt_hs512() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), "val1".to_string());
        p1.insert("key22".to_string(), "val2".to_string());
        p1.insert("key33".to_string(), "val3".to_string());

        let secret = "secret123456";
        let header = Header::new(Algorithm::HS512);
        let jwt1 = encode(header, secret, p1.clone());
        let maybe_res = decode(jwt1, secret, Algorithm::HS512);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encode_and_decode_jwt_rs256() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), "val1".to_string());
        p1.insert("key22".to_string(), "val2".to_string());
        p1.insert("key33".to_string(), "val3".to_string());
        let header = Header::new(Algorithm::RS256);

        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_str().unwrap().to_string();

        let jwt1 = encode(header, RSA_PRIVATE_KEY, p1.clone());
        let maybe_res = decode(jwt1, RSA_PUBLIC_KEY, Algorithm::RS256);
        assert!(maybe_res.is_ok());
    }


    static RS256_JWT: &str = include_str!("../test/valid_rs256.jwt");
    #[test]
    fn test_decode_valid_jwt_rs256() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        let header = Header::new(Algorithm::RS256);
        let jwt = encode(header, RSA_PRIVATE_KEY, p1.clone());
        assert_eq!(RS256_JWT, jwt);
    }

    #[test]
    fn test_decode_valid_jwt_rs256_and_check_deeply() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        let h1 = Header::new(Algorithm::RS256);
        let res = decode(RS256_JWT, RSA_PUBLIC_KEY, Algorithm::RS256);
        match res {
            Ok((h2, p2)) => {
                assert_eq!(h1.typ, h2.typ);
                assert_eq!(h1.alg, h2.alg);
                for (k, v) in &p1 {
                    assert_eq!(true, p2.contains_key(k));
                    assert_eq!(v, p2.get(k).unwrap());
                }
            }
            Err(e) => panic!(e),
        }
    }


    #[test]
    fn test_encode_and_decode_jwt_ec() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), "val1".to_string());
        p1.insert("key22".to_string(), "val2".to_string());
        p1.insert("key33".to_string(), "val3".to_string());
        let header = Header::new(Algorithm::ES512);

        let jwt1 = encode(header, EC_PRIVATE_KEY, p1.clone());
        let maybe_res = decode(jwt1, EC_PUBLIC_KEY, Algorithm::ES512);
        assert!(maybe_res.is_ok());
    }

    static EC_PRIVATE_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.private.key.pem");
    static EC_PUBLIC_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.public.key.pem");
    static RSA_PRIVATE_KEY: &str = include_str!("../test/my_rsa_2048_key.pem");
    static RSA_PUBLIC_KEY: &str = include_str!("../test/my_rsa_public_2048_key.pem");
}
