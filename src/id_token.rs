use {Value, Decoder, Error, Header, Payload, Number, Encoder, Algorithm, PKey, uuid};
use std::time::{SystemTime, UNIX_EPOCH};



pub struct IDTokenDecoder {
    pub decoder: Decoder,
    pub valid_issuer: String,
    pub audience: String,
    pub nonce: Option<String>,
    pub acr: Option<String>,
    pub azp: Option<String>,
}

impl IDTokenDecoder {
    pub fn from_pem<T: AsRef<[u8]>, F: Into<String>>(
        pem: T,
        valid_issuer: F,
        valid_audience: F,
    ) -> Result<IDTokenDecoder, Error> {
        let decoder = Decoder::from_pem(pem.as_ref())?;
        Ok(IDTokenDecoder {
            decoder: decoder,
            valid_issuer: valid_issuer.into(),
            audience: valid_audience.into(),
            nonce: None,
            acr: None,
            azp: None,
        })
    }


    pub fn from_key<F: Into<String>>(
        key: PKey,
        valid_issuer: F,
        valid_audience: F,
    ) -> IDTokenDecoder {
        let decoder = Decoder::from_public_key(key);
        IDTokenDecoder {
            decoder: decoder,
            valid_issuer: valid_issuer.into(),
            audience: valid_audience.into(),
            nonce: None,
            acr: None,
            azp: None,
        }
    }


    pub fn from_hmac<T: AsRef<[u8]>, F: Into<String>>(
        hmac: T,
        valid_issuer: F,
        valid_audience: F,
    ) -> Result<IDTokenDecoder, Error> {
        let decoder = Decoder::from_hmac_secret(hmac.as_ref())?;
        Ok(IDTokenDecoder {
            decoder: decoder,
            valid_issuer: valid_issuer.into(),
            audience: valid_audience.into(),
            nonce: None,
            acr: None,
            azp: None,
        })
    }

    fn get_str_claim<'a>(&self, payload: &'a Payload, claim: &str) -> Result<&'a str, Error> {
        if let Some(val) = payload.get(claim) {
            val.as_str().ok_or(Error::JWTInvalid)
        } else {
            Err(Error::JWTInvalid)
        }
    }

    fn get_u64_claim(&self, payload: &Payload, claim: &str) -> Result<u64, Error> {
        if let Some(val) = payload.get(claim) {
            val.as_u64().ok_or(Error::JWTInvalid)
        } else {
            Err(Error::JWTInvalid)
        }
    }

    pub fn decode<T: AsRef<str>>(&self, token: T) -> Result<IDToken, Error> {

        let (header, payload) = self.decoder.decode(token)?;

        //needs to be a block to please the borrow checker
        {
            // audience claim can be both array and string value.
            if let Some(audiences_value) = payload.get("aud") {
                let valid_audience = if audiences_value.is_array() {
                    audiences_value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| {
                            v.as_str().expect("could not convert entry in string array")
                        })
                        .any(|val| val == &self.audience)
                } else if audiences_value.is_string() {
                    audiences_value.as_str().unwrap() == &self.audience
                } else {
                    return Err(Error::JWTInvalid);
                };
                if !valid_audience {
                    return Err(Error::JWTInvalid);
                }
            } else {
                return Err(Error::JWTInvalid);
            }


            let issuer = self.get_str_claim(&payload, "iss")?;
            if issuer != self.valid_issuer {
                return Err(Error::IssuerInvalid);
            }

            let issued_at = self.get_u64_claim(&payload, "iat")?;
            if issued_at > get_current_time_seconds() {
                return Err(Error::JWTInvalid);
            }

            let expires = self.get_u64_claim(&payload, "exp")?;
            if expires < get_current_time_seconds() {
                return Err(Error::ExpirationInvalid);
            }

            if let Some(not_before_value) = payload.get("nbf") {
                let not_before = not_before_value.as_u64().ok_or(Error::JWTInvalid)?;
                if not_before > get_current_time_seconds() {
                    return Err(Error::JWTInvalid);
                }
            }



            if let Some(ref nonce) = self.nonce {
                let payload_nonce = self.get_str_claim(&payload, "nonce")?;
                if payload_nonce != nonce {
                    return Err(Error::JWTInvalid);
                }
            }


            if let Some(ref azp) = self.azp {
                let payload_azp = self.get_str_claim(&payload, "azp")?;
                if payload_azp != azp {
                    return Err(Error::JWTInvalid);
                }
            }

            if let Some(ref acr) = self.acr {

                let payload_acr = self.get_str_claim(&payload, "acr")?;
                if payload_acr != acr {
                    return Err(Error::JWTInvalid);
                }
            }


        }

        let result = IDToken {
            header: header,
            payload: payload,
        };
        Ok(result)
    }
}

pub struct IDToken {
    pub header: Header,
    pub payload: Payload,
}


impl IDToken {
    pub fn build(
        issuer: &str,
        subject_identifier: &str,
        audiences: &[&str],
        duration: u64,
    ) -> IDTokenBuilder {
        IDTokenBuilder::new(issuer, subject_identifier, audiences, duration)
    }

    pub fn issuer(&self) -> &str {
        self.payload.get("iss").unwrap().as_str().expect(
            "this should be a string",
        )
    }

    pub fn subject_identifier(&self) -> &str {
        self.payload.get("sub").unwrap().as_str().unwrap()
    }

    pub fn audiences(&self) -> Vec<&str> {
        let raw_audiences = self.payload.get("aud").unwrap().as_array().unwrap();
        raw_audiences
            .into_iter()
            .map(|a| a.as_str().unwrap())
            .collect()
    }


    pub fn expiration_time(&self) -> u64 {
        self.get_sure_u64_value("exp")
    }

    pub fn issued_at(&self) -> u64 {
        self.get_sure_u64_value("iat")
    }

    pub fn nonce(&self) -> Option<&str> {
        self.get_possible_str_value("nonce")
    }

    pub fn acr(&self) -> Option<&str> {
        self.get_possible_str_value("acr")
    }

    pub fn amr(&self) -> Vec<&str> {
        let possible_amr = self.payload.get("amr");

        if possible_amr.is_none() {
            return Vec::new();
        }
        possible_amr
            .unwrap()
            .as_array()
            .unwrap()
            .into_iter()
            .map(|a| a.as_str().unwrap())
            .collect()
    }

    pub fn not_before(&self) -> Option<u64> {
        self.payload.get("nbf").map(|v| v.as_u64().unwrap())
    }

    pub fn jwt_identifier(&self) -> Option<&str> {
        self.get_possible_str_value("jti")
    }

    pub fn azp(&self) -> Option<&str> {
        self.get_possible_str_value("azp")
    }

    fn get_possible_str_value(&self, key: &str) -> Option<&str> {
        self.payload.get(key).map(|v| v.as_str().unwrap())
    }

    fn get_sure_u64_value(&self, key: &str) -> u64 {
        self.payload.get(key).unwrap().as_u64().unwrap()
    }
}


fn get_current_time_seconds() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect(
        "Time went backwards",
    );
    since_the_epoch.as_secs()
}

pub struct IDTokenBuilder {
    payload: Payload,
    duration: u64,
}


impl IDTokenBuilder {
    fn new(
        issuer: &str,
        subject_identifier: &str,
        audiences: &[&str],
        duration: u64,
    ) -> IDTokenBuilder {
        let mut payload = Payload::new();
        let now = get_current_time_seconds();
        let iat = Number::from(now);
        let nbf = Number::from(now);
        let jit = uuid::Uuid::new_v4().to_string();
        payload.insert("iss".to_string(), Value::String(issuer.to_string()));
        payload.insert(
            "sub".to_string(),
            Value::String(subject_identifier.to_string()),
        );
        let audience_values = audiences
            .into_iter()
            .map(|a| Value::String(a.to_string()))
            .collect();
        payload.insert("aud".to_string(), Value::Array(audience_values));
        payload.insert("iat".to_string(), Value::Number(iat));
        payload.insert("nbf".to_string(), Value::Number(nbf));
        payload.insert("jti".to_string(), Value::String(jit));
        IDTokenBuilder {
            payload: payload,
            duration: duration,
        }
    }

    pub fn auth_time(mut self, time: u64) -> IDTokenBuilder {
        let auth_number = Number::from(time);
        self.payload.insert(
            "auth_time".to_string(),
            Value::Number(auth_number),
        );
        self
    }



    pub fn not_before(mut self, time: u64) -> IDTokenBuilder {
        let nbf_number = Number::from(time);
        self.payload.insert(
            "nbf".to_string(),
            Value::Number(nbf_number),
        );
        self
    }

    pub fn nonce<T: Into<String>>(mut self, nonce: T) -> IDTokenBuilder {
        self.payload.insert(
            "nonce".to_string(),
            Value::String(nonce.into()),
        );
        self
    }

    pub fn acr<T: Into<String>>(mut self, value: T) -> IDTokenBuilder {
        self.payload.insert(
            "acr".to_string(),
            Value::String(value.into()),
        );
        self
    }

    pub fn amr(mut self, value: &[&str]) -> IDTokenBuilder {
        let items = value
            .into_iter()
            .map(|item| Value::String(item.to_string()))
            .collect();
        self.payload.insert("amr".to_string(), Value::Array(items));
        self
    }

    pub fn azp<T: Into<String>>(mut self, value: T) -> IDTokenBuilder {
        self.payload.insert(
            "azp".to_string(),
            Value::String(value.into()),
        );
        self
    }

    pub fn to_token_structure(mut self, alg: Algorithm) -> IDToken {
        self.add_exp_field();
        IDToken {
            header: Header::new(alg),
            payload: self.payload,
        }
    }

    fn add_exp_field(&mut self) {
        let nbf = self.payload.get("nbf").unwrap().as_u64().unwrap();
        let exp = Number::from(nbf + self.duration);
        self.payload.insert("exp".to_string(), Value::Number(exp));
    }

    pub fn sign_with_pem<T: AsRef<[u8]>>(
        mut self,
        pem: T,
        alg: Algorithm,
    ) -> Result<String, Error> {
        self.add_exp_field();
        let encoder = Encoder::from_raw_private_key(pem.as_ref(), alg)?;
        encoder.encode(self.payload)
    }


    pub fn sign_with_private_key(mut self, key: PKey, alg: Algorithm) -> Result<String, Error> {
        self.add_exp_field();

        let encoder = Encoder::from_private_key(key, alg);
        encoder.encode(self.payload)
    }

    pub fn sign_with_hmac<T: AsRef<[u8]>>(
        mut self,
        key: T,
        alg: Algorithm,
    ) -> Result<String, Error> {
        self.add_exp_field();
        let encoder = Encoder::from_raw_private_key(key.as_ref(), alg)?;
        encoder.encode(self.payload)
    }
}

#[cfg(test)]
mod tests {

    use super::{Algorithm, IDToken, IDTokenDecoder, get_current_time_seconds, Error};

    #[test]
    fn it_should_create_a_valid_id_token() {
        let token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 20,
        ).acr("urn:mace:incommon:iap:silver")
            .amr(&["password"])
            .azp("rp123")
            .to_token_structure(Algorithm::ES256);
        assert_eq!(token.audiences()[0], "rp123");
        assert_eq!(token.subject_identifier(), "user123");
        assert_eq!(token.issued_at(), get_current_time_seconds());
        assert_eq!(
            token.expiration_time(),
            get_current_time_seconds() + 60 * 20
        );
    }


    static EC_PRIVATE_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.private.key.pem");
    static EC_PUBLIC_KEY: &str = include_str!("../test/ec_x9_62_prime256v1.public.key.pem");

    #[test]
    fn encode_and_decode_id_token() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .amr(&["password"])
            .azp("rp123")
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        println!("{}", id_token);

        let id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .expect("should not fail");
        let token_struct = id_token_decoder.decode(id_token).expect(
            "verification should not fail",
        );
        assert_eq!(token_struct.acr().unwrap(), "urn:mace:incommon:iap:silver");
        assert_eq!(token_struct.amr()[0], "password");
        assert_eq!(token_struct.azp().unwrap(), "rp123");

    }


    static RS_256_TOKEN: &str = include_str!("../test/invalid_id_token.jwt");
    static RS_PUBLIC_KEY: &str = include_str!("../test/my_rsa_public_2048_key.pem");
    #[test]
    fn fail_on_invalid_id_token() {
        let id_token_decoder =
            IDTokenDecoder::from_pem(RS_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .expect("should not fail");
        let result = id_token_decoder.decode(RS_256_TOKEN);

        assert!(result.is_err());

        match result.err().unwrap() {
            Error::JWTInvalid => {}
            _ => panic!("wrong error"),
        }
    }

    static EXPIRED_EC_TOKEN: &str = include_str!("../test/expired_ec.jwt");
    #[test]
    fn fail_on_expired_id_token() {
        let id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        let result = id_token_decoder.decode(EXPIRED_EC_TOKEN);

        assert!(result.is_err());

        match result.err().unwrap() {
            Error::ExpirationInvalid => {}
            _ => panic!("wrong error"),
        }

    }


    #[test]
    fn fail_on_missing_acr_if_expected() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).amr(&["password"])
            .azp("rp123")
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.acr = Some("urn:mace:incommon:iap:silver".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }


    #[test]
    fn fail_on_wrong_acr() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("0")
            .amr(&["password"])
            .azp("rp123")
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.acr = Some("urn:mace:incommon:iap:silver".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }

    #[test]
    fn pass_on_correct_acr() {

        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .amr(&["password"])
            .azp("rp123")
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.acr = Some("urn:mace:incommon:iap:silver".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_ok());
    }

    #[test]
    fn fail_on_missing_azp_if_expected() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.azp = Some("rp567".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }


    #[test]
    fn fail_on_incorrect_azp() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .azp("rp123")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.azp = Some("rp567".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }

    #[test]
    fn pass_on_correct_azp() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .azp("rp123")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let mut id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        id_token_decoder.azp = Some("rp123".to_string());

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_ok());
    }



    #[test]
    fn fail_on_incorrect_audience() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .azp("rp123")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp567")
                .unwrap();

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }


    #[test]
    fn fail_on_if_token_used_before_nbf() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .not_before(get_current_time_seconds() + 50 * 60)
            .azp("rp123")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_err());
    }


    #[test]
    fn pass_if_nbf_is_valid() {
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60 * 2,
        ).acr("urn:mace:incommon:iap:silver")
            .not_before(get_current_time_seconds() - 10)
            .azp("rp123")
            .amr(&["password"])
            .sign_with_pem(EC_PRIVATE_KEY, Algorithm::ES256)
            .expect("signing should work");

        let id_token_decoder =
            IDTokenDecoder::from_pem(EC_PUBLIC_KEY, "https://authority.example.org/auth", "rp123")
                .unwrap();

        let decode_result = id_token_decoder.decode(id_token);
        assert!(decode_result.is_ok());
    }

    #[test]
    fn expires_should_be_relative_to_nbf() {
        let now = get_current_time_seconds();
        let id_token = IDToken::build(
            "https://authority.example.org/auth",
            "user123",
            &["rp123"],
            60,
        ).acr("urn:mace:incommon:iap:silver")
            .not_before(now + 15)
            .azp("rp123")
            .amr(&["password"])
            .to_token_structure(Algorithm::ES256);
        let diff = id_token.expiration_time() - id_token.not_before().unwrap();
        assert_eq!(diff, 60);
    }

}