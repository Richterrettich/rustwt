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
use std::fs::File;
use std::io::Read;
use std::str;

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

#[derive(Serialize, Deserialize, Clone, Copy)]
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

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match *self {
            Algorithm::HS256 => "HS256".to_string(),
            Algorithm::HS384 => "HS384".to_string(),
            Algorithm::HS512 => "HS512".to_string(),
            Algorithm::RS256 => "RS256".to_string(),
            Algorithm::RS384 => "RS384".to_string(),
            Algorithm::RS512 => "RS512".to_string(),
            Algorithm::ES256 => "ES256".to_string(),
            Algorithm::ES384 => "ES384".to_string(),
            Algorithm::ES512 => "ES512".to_string(),
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

pub fn encode(header: Header, key: String, payload: Payload) -> String {
    let signing_input = get_signing_input(payload, &header.alg);
    let pkey = match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            PKey::hmac(key.as_bytes()).unwrap()
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => rsa_key(key),
        Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => es_key(key),
    };
    let signature = sign(&signing_input, pkey, header.alg.get_hash());


    format!("{}.{}", signing_input, signature)
}

pub fn decode(
    encoded_token: String,
    key: String,
    algorithm: Algorithm,
) -> Result<(Header, Payload), Error> {
    match decode_segments(&encoded_token[..]) {
        Some((header, payload, signature, signing_input)) => {
            if !verify_signature(algorithm, signing_input, &signature, key) {
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


fn rsa_key(private_key_path: String) -> PKey {
    let buffer = read_pem(&private_key_path[..]);
    let rsa = Rsa::private_key_from_pem(&buffer).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn es_key(private_key_path: String) -> PKey {
    let raw_key = read_pem(&private_key_path[..]);
    let ec_key =
        EcKey::private_key_from_pem(&raw_key).expect("could not convert to EC private key");
    PKey::from_ec_key(ec_key).expect("could not convert EC private key")
}

fn sign(data: &str, private_key: PKey, digest: MessageDigest) -> String {
    let mut signer = Signer::new(digest, &private_key).unwrap();
    signer.update(data.as_bytes()).unwrap();
    let signature = signer.finish().unwrap();
    base64::encode_config(&signature, base64::URL_SAFE_NO_PAD)
}

fn read_pem(private_key_path: &str) -> Vec<u8> {
    let mut file = File::open(private_key_path).unwrap();
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    buffer
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
    // let signature = &crypto_segment.as_bytes().from_base64().unwrap();
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

fn sign_hmac2(data: &str, key: String, algorithm: Algorithm) -> Vec<u8> {
    let stp = match algorithm {
        Algorithm::HS256 => MessageDigest::sha256(),
        Algorithm::HS384 => MessageDigest::sha384(),
        Algorithm::HS512 => MessageDigest::sha512(),
        _ => panic!("Invalid hmac algorithm"),
    };

    let pkey = PKey::hmac(key.as_bytes()).unwrap();
    let mut signer = Signer::new(stp, &pkey).unwrap();
    signer.update(data.as_bytes()).unwrap();
    signer.finish().unwrap()
}

fn verify_signature(
    algorithm: Algorithm,
    signing_input: String,
    signature: &[u8],
    public_key: String,
) -> bool {
    match algorithm {

        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let signature2 = sign_hmac2(&signing_input, public_key, algorithm);
            secure_compare(signature, &signature2)
        }

        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let mut file = File::open(public_key).unwrap();
            let mut buffer: Vec<u8> = Vec::new();
            file.read_to_end(&mut buffer).unwrap();
            let rsa = Rsa::public_key_from_pem(&buffer).unwrap();
            let key = PKey::from_rsa(rsa).unwrap();

            let digest = get_sha_algorithm(algorithm);
            let mut verifier = Verifier::new(digest, &key).unwrap();
            verifier.update(signing_input.as_bytes()).unwrap();
            verifier.finish(&signature).unwrap()
        }
        Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => {
            let raw_pem = read_pem(&public_key[..]);
            let key =
                PKey::public_key_from_pem(&raw_pem).expect("could not convert ec key to pkey");

            let digest = get_sha_algorithm(algorithm);
            let mut verifier = Verifier::new(digest, &key).unwrap();
            verifier.update(signing_input.as_bytes()).unwrap();
            verifier.finish(&signature).unwrap()
        }
    }
}

fn get_sha_algorithm(alg: Algorithm) -> MessageDigest {
    match alg {
        Algorithm::RS256 | Algorithm::ES256 => MessageDigest::sha256(),
        Algorithm::RS384 | Algorithm::ES384 => MessageDigest::sha384(),
        Algorithm::RS512 | Algorithm::ES512 => MessageDigest::sha512(),
        _ => panic!("Invalid rsa algorithm"),
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
        let jwt1 = encode(header, secret.to_string(), p1.clone());
        let maybe_res = decode(
            String::from(jwt1.trim()),
            secret.to_string(),
            Algorithm::HS256,
        );
        assert!(maybe_res.is_ok());
    }

    static HS256_JWT: &'static str = include_str!("../test/valid_hs256.jwt");
    #[test]
    fn test_decode_valid_jwt_hs256() {
        let mut p1 = Payload::new();
        p1.insert("key11".to_string(), "val1".to_string());
        p1.insert("key22".to_string(), "val2".to_string());
        let secret = "secret123";
        let maybe_res = decode(HS256_JWT.to_string(), secret.to_string(), Algorithm::HS256);
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
        let jwt1 = encode(header, secret.to_string(), p1.clone());
        let maybe_res = decode(jwt1, secret.to_string(), Algorithm::HS384);
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
        let jwt1 = encode(header, secret.to_string(), p1.clone());
        let maybe_res = decode(jwt1, secret.to_string(), Algorithm::HS512);
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

        let jwt1 = encode(header, get_rsa_256_private_key_full_path(), p1.clone());
        let maybe_res = decode(jwt1, get_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(maybe_res.is_ok());
    }


    static RS256_JWT: &'static str = include_str!("../test/valid_rs256.jwt");
    #[test]
    fn test_decode_valid_jwt_rs256() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        let header = Header::new(Algorithm::RS256);
        let jwt = encode(header, get_rsa_256_private_key_full_path(), p1.clone());
        assert_eq!(RS256_JWT, jwt);
    }

    #[test]
    fn test_decode_valid_jwt_rs256_and_check_deeply() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), "val1".to_string());
        p1.insert("key2".to_string(), "val2".to_string());
        let h1 = Header::new(Algorithm::RS256);
        let res = decode(
            RS256_JWT.to_string(),
            get_rsa_256_public_key_full_path(),
            Algorithm::RS256,
        );
        match res {
            Ok((h2, p2)) => {
                assert_eq!(h1.typ, h2.typ);
                assert_eq!(h1.alg.to_string(), h2.alg.to_string()); //todo implement ==
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

        let jwt1 = encode(header, get_ec_private_key_path(), p1.clone());
        let maybe_res = decode(jwt1, get_ec_public_key_path(), Algorithm::ES512);
        assert!(maybe_res.is_ok());
    }

    fn get_ec_private_key_path() -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("ec_x9_62_prime256v1.private.key.pem");
        path.to_str().unwrap().to_string()
    }

    fn get_ec_public_key_path() -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("ec_x9_62_prime256v1.public.key.pem");
        path.to_str().unwrap().to_string()
    }

    fn get_rsa_256_private_key_full_path() -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_str().unwrap().to_string()
    }

    fn get_rsa_256_public_key_full_path() -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_public_2048_key.pem");
        path.to_str().unwrap().to_string()
    }
}
