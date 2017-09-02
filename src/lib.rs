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


//! Welcome to rustwt - A battaries included JWT library for rust.
//! # Getting started
//!
//! If you just want to create jwt or id tokens, use the [id_token](./id_token/index.html) module.
//! If you want to create a custom token (with just verification), use the  [Encoder](./struct.Encoder.html)
//! and [Decoder](./struct.Decoder.html) structs.

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate time;
extern crate openssl;
extern crate base64;
extern crate uuid;


use std::collections::BTreeMap;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::error::ErrorStack;
use openssl::memcmp;
use std::convert::From;

pub use serde_json::{Value, Number};

pub mod id_token;

pub type Payload = BTreeMap<String, Value>;



/// Struct representing a JWT Header.
#[derive(Serialize, Deserialize)]
pub struct Header {
    alg: Algorithm,
    typ: String,
}

impl Header {
    /// Create a new Header.
    /// The typ field is always "JWT".
    pub fn new(alg: Algorithm) -> Header {
        Header {
            alg: alg,
            typ: String::from("JWT"),
        }
    }
}


/// Enum representing JWT signature algorithms.
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

/// Enum representing Encoding/Decoding errors.
#[derive(Debug)]
pub enum Error {
    SignatureExpired,
    SignatureInvalid,
    JWTInvalid,
    IssuerInvalid,
    ExpirationInvalid,
    AudienceInvalid,
    OpensslError(ErrorStack),
}


impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::OpensslError(err)
    }
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
            Error::OpensslError(ref e) => e.description(),
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
            Error::OpensslError(ref e) => e.fmt(f),
        }
    }
}


/// Low level structure for encoding JWT.
/// Use this struct if you want to have full control over the payload used for your JWT.
/// In most scenarios, you are better of using [id_token](./id_token/struct.IDTokenBuilder.html) though.
/// # Example public key signature
///
/// ```rust
/// use rustwt::{Payload,Encoder,Algorithm,Decoder,Value};
/// // you can use RSA keys as well. Just adjust the algorithm.
/// let ec_private_key: &str = include_str!("../test/ec_x9_62_prime256v1.private.key.pem");
/// let ec_public_key: &str = include_str!("../test/ec_x9_62_prime256v1.public.key.pem");
/// let mut p1 = Payload::new();
/// p1.insert("key12".to_string(), Value::String("val1".to_string()));
/// p1.insert("key22".to_string(), Value::String("val2".to_string()));
/// p1.insert("key33".to_string(), Value::String("val3".to_string()));
/// let encoder = Encoder::from_raw_private_key(ec_private_key, Algorithm::ES256).unwrap();
/// let decoder = Decoder::from_pem(ec_public_key).unwrap();
/// let jwt1 = encoder.encode(p1.clone()).expect("could not encode token");
/// let maybe_res = decoder.decode(jwt1);
/// ```
///
/// # Example hmac
/// ```rust
/// use rustwt::{Payload,Encoder,Algorithm,Decoder,Value};
/// let secret: &str = "secret123";
/// let mut p1 = Payload::new();
/// p1.insert("key12".to_string(), Value::String("val1".to_string()));
/// p1.insert("key22".to_string(), Value::String("val2".to_string()));
/// p1.insert("key33".to_string(), Value::String("val3".to_string()));
/// let encoder = Encoder::from_raw_private_key(secret, Algorithm::HS256).unwrap();
/// let decoder = Decoder::from_hmac_secret(secret).unwrap();
/// let jwt1 = encoder.encode(p1.clone()).expect("could not encode token");
/// let maybe_res = decoder.decode(jwt1);
/// ```
pub struct Encoder {
    key: PKey,
    algorithm: Algorithm,
}


impl Encoder {
    /// Create a new Encoder from a raw private key and an Algorithm.
    /// The private key can either be a HMAC or a PEM encoded RSA/EC key.
    pub fn from_raw_private_key<T: ?Sized + AsRef<[u8]>>(
        raw_key: &T,
        alg: Algorithm,
    ) -> Result<Encoder, Error> {
        let kr = raw_key.as_ref();
        let pkey = match alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => PKey::hmac(kr)?,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 |
            Algorithm::ES384 | Algorithm::ES512 => PKey::private_key_from_pem(kr)?,
        };
        Ok(Encoder {
            key: pkey,
            algorithm: alg,
        })
    }

    /// Create a new Encoder from a PKey struct.
    pub fn from_private_key(pkey: PKey, alg: Algorithm) -> Encoder {
        Encoder {
            key: pkey,
            algorithm: alg,
        }
    }

    /// Encodes a payload into a JWT.
    pub fn encode(&self, payload: Payload) -> Result<String, Error> {
        let signing_input = get_signing_input(payload, &self.algorithm);
        let signature = sign_and_encode(&signing_input, &self.key, self.algorithm.get_hash())?;
        Ok(format!("{}.{}", signing_input, signature))
    }
}




/// Basic structure for decoding JWT.
///
/// # Example public key signature
///
/// ```rust
/// use rustwt::{Payload,Encoder,Algorithm,Decoder,Value};
/// // you can use RSA keys as well. Just adjust the algorithm.
/// let ec_private_key: &str = include_str!("../test/ec_x9_62_prime256v1.private.key.pem");
/// let ec_public_key: &str = include_str!("../test/ec_x9_62_prime256v1.public.key.pem");
/// let mut p1 = Payload::new();
/// p1.insert("key12".to_string(), Value::String("val1".to_string()));
/// p1.insert("key22".to_string(), Value::String("val2".to_string()));
/// p1.insert("key33".to_string(), Value::String("val3".to_string()));
/// let encoder = Encoder::from_raw_private_key(ec_private_key, Algorithm::ES256).unwrap();
/// let decoder = Decoder::from_pem(ec_public_key).unwrap();
/// let jwt1 = encoder.encode(p1.clone()).expect("could not encode token");
/// let maybe_res = decoder.decode(jwt1);
/// ```
///
/// # Example hmac
/// ```rust
/// use rustwt::{Payload,Encoder,Algorithm,Decoder,Value};
/// let secret: &str = "secret123";
/// let mut p1 = Payload::new();
/// p1.insert("key12".to_string(), Value::String("val1".to_string()));
/// p1.insert("key22".to_string(), Value::String("val2".to_string()));
/// p1.insert("key33".to_string(), Value::String("val3".to_string()));
/// let encoder = Encoder::from_raw_private_key(secret, Algorithm::HS256).unwrap();
/// let decoder = Decoder::from_hmac_secret(secret).unwrap();
/// let jwt1 = encoder.encode(p1.clone()).expect("could not encode token");
/// let maybe_res = decoder.decode(jwt1);
/// ```
pub struct Decoder {
    key: PKey,
}

impl Decoder {
    pub fn from_hmac_secret<T: ?Sized + AsRef<[u8]>>(secret: &T) -> Result<Decoder, Error> {
        let kr = secret.as_ref();
        let key = PKey::hmac(kr)?;
        Ok(Decoder { key: key })
    }
    pub fn from_pem<T: ?Sized + AsRef<[u8]>>(raw_key: &T) -> Result<Decoder, Error> {
        let kr = raw_key.as_ref();
        let pkey = PKey::public_key_from_pem(kr)?;
        Ok(Decoder { key: pkey })
    }

    pub fn from_public_key(key: PKey) -> Decoder {
        Decoder { key: key }
    }

    /// This function decodes a valid base64 encoded token.
    /// If the token is invalid, an appropriate error will be returned.
    pub fn decode<T: AsRef<str>>(&self, token: T) -> Result<(Header, Payload), Error> {
        match decode_segments(token.as_ref()) {
            Some((header, payload, signature, signing_input)) => {
                if !self.verify_signature(
                    &signing_input[..],
                    &signature,
                    header.alg,
                )?
                {
                    return Err(Error::SignatureInvalid);
                }
                Ok((header, payload))
            }

            None => Err(Error::JWTInvalid),
        }
    }

    fn verify_signature(
        &self,
        signing_input: &str,
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool, Error> {
        match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let signature2 = sign(&signing_input, &self.key, algorithm.get_hash())?;
                Ok(memcmp::eq(signature, &signature2))
            }
            _ => {
                let mut verifier = Verifier::new(algorithm.get_hash(), &self.key)?;
                verifier.update(signing_input.as_bytes())?;
                verifier.finish(&signature).map_err(
                    |e| Error::OpensslError(e),
                )
            }
        }
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

fn sign(data: &str, private_key: &PKey, digest: MessageDigest) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(digest, &private_key)?;
    signer.update(data.as_bytes())?;
    signer.finish()
}

fn sign_and_encode(data: &str, private_key: &PKey, digest: MessageDigest) -> Result<String, Error> {
    let raw = sign(data, private_key, digest)?;
    Ok(base64::encode_config(&raw, base64::URL_SAFE_NO_PAD))
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




#[cfg(test)]
mod tests {
    extern crate time;

    use super::Header;
    use super::Payload;
    use super::Algorithm;
    use super::Encoder;
    use super::Decoder;
    use super::Value;

    #[test]
    fn test_encode_and_decode_jwt_hs256() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), Value::String("val2".to_string()));
        p1.insert("key2".to_string(), Value::String("val2".to_string()));
        p1.insert("key3".to_string(), Value::String("val3".to_string()));

        let secret = "secret123";
        let encoder = Encoder::from_raw_private_key(secret, Algorithm::HS256).unwrap();
        let decoder = Decoder::from_hmac_secret(secret).unwrap();
        let jwt1 = encoder.encode(p1.clone()).expect("error while encoding.");
        let maybe_res = decoder.decode(jwt1.trim());
        assert!(maybe_res.is_ok());
    }

    static HS256_JWT: &'static str = include_str!("../test/valid_hs256.jwt");
    #[test]
    fn test_decode_valid_jwt_hs256() {
        let mut p1 = Payload::new();
        p1.insert("key11".to_string(), Value::String("val1".to_string()));
        p1.insert("key22".to_string(), Value::String("val2".to_string()));
        let secret = "secret123";
        let decoder = Decoder::from_hmac_secret(secret).unwrap();
        let maybe_res = decoder.decode(HS256_JWT);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encode_and_decode_jwt_hs384() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), Value::String("val1".to_string()));
        p1.insert("key2".to_string(), Value::String("val2".to_string()));
        p1.insert("key3".to_string(), Value::String("val3".to_string()));

        let secret = "secret123";
        let encoder = Encoder::from_raw_private_key(secret, Algorithm::HS384).unwrap();
        let decoder = Decoder::from_hmac_secret(secret).unwrap();
        let jwt1 = encoder.encode(p1.clone()).unwrap();
        let maybe_res = decoder.decode(jwt1);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encode_and_decode_jwt_hs512() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), Value::String("val1".to_string()));
        p1.insert("key22".to_string(), Value::String("val2".to_string()));
        p1.insert("key33".to_string(), Value::String("val3".to_string()));

        let secret = "secret123456";
        let encoder = Encoder::from_raw_private_key(secret, Algorithm::HS512).unwrap();
        let decoder = Decoder::from_hmac_secret(secret).unwrap();
        let jwt1 = encoder.encode(p1.clone()).unwrap();
        let maybe_res = decoder.decode(jwt1);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encode_and_decode_jwt_rs256() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), Value::String("val1".to_string()));
        p1.insert("key22".to_string(), Value::String("val2".to_string()));
        p1.insert("key33".to_string(), Value::String("val3".to_string()));

        let encoder = Encoder::from_raw_private_key(RSA_PRIVATE_KEY, Algorithm::RS256).unwrap();
        let decoder = Decoder::from_pem(RSA_PUBLIC_KEY).unwrap();
        let jwt1 = encoder.encode(p1.clone()).unwrap();
        let maybe_res = decoder.decode(jwt1);
        assert!(maybe_res.is_ok());
    }


    static RS256_JWT: &str = include_str!("../test/valid_rs256.jwt");
    #[test]
    fn test_encode_valid_jwt_rs256() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), Value::String("val1".to_string()));
        p1.insert("key2".to_string(), Value::String("val2".to_string()));
        let encoder = Encoder::from_raw_private_key(RSA_PRIVATE_KEY, Algorithm::RS256).unwrap();
        let jwt = encoder.encode(p1.clone()).expect("error while encoding");
        assert_eq!(RS256_JWT, jwt);
    }

    #[test]
    fn test_decode_valid_jwt_rs256_and_check_deeply() {
        let mut p1 = Payload::new();
        p1.insert("key1".to_string(), Value::String("val1".to_string()));
        p1.insert("key2".to_string(), Value::String("val2".to_string()));
        let h1 = Header::new(Algorithm::RS256);
        let decoder = Decoder::from_pem(RSA_PUBLIC_KEY).unwrap();
        let res = decoder.decode(RS256_JWT);
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

    static MANIPULATED_RS256_JWT: &str = include_str!("../test/manipulated_rs256.jwt");
    #[test]
    fn it_should_fail_if_the_rsa_signature_is_invalid() {
        let decoder = Decoder::from_pem(RSA_PUBLIC_KEY).unwrap();
        let res = decoder.decode(MANIPULATED_RS256_JWT);
        assert!(res.is_err());

        let e = res.err().unwrap();

        let right_error = match e {
            super::Error::SignatureInvalid => true,
            _ => false,
        };
        assert!(right_error);
    }

    #[test]
    fn test_encode_and_decode_jwt_ec() {
        let mut p1 = Payload::new();
        p1.insert("key12".to_string(), Value::String("val1".to_string()));
        p1.insert("key22".to_string(), Value::String("val2".to_string()));
        p1.insert("key33".to_string(), Value::String("val3".to_string()));
        let encoder = Encoder::from_raw_private_key(EC_PRIVATE_KEY, Algorithm::ES256).unwrap();
        let decoder = Decoder::from_pem(EC_PUBLIC_KEY).unwrap();
        let jwt1 = encoder.encode(p1.clone()).expect("could not encode token");
        let maybe_res = decoder.decode(jwt1);
        assert!(maybe_res.is_ok());
    }

    static EC_PRIVATE_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.private.key.pem");
    static EC_PUBLIC_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.public.key.pem");
    static RSA_PRIVATE_KEY: &str = include_str!("../test/my_rsa_2048_key.pem");
    static RSA_PUBLIC_KEY: &str = include_str!("../test/my_rsa_public_2048_key.pem");
}
