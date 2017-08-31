Rustwt
================================================
[![Build Status](https://travis-ci.org/Richterrettich/rusty_jwt.svg?branch=master)](https://travis-ci.org/Richterrettich/rusty_jwt)

This is a hard fork of https://github.com/GildedHonour/frank_jwt


Implementation of [JSON Web Tokens](http://jwt.io) in Rust.

## Algorithms and features supported
- [x] HS256
- [x] HS384
- [x] HS512
- [x] RS256
- [x] RS384
- [x] RS512
- [x] ES256
- [x] ES384
- [x] ES512
- [x] Sign
- [x] Verify
- [x] iss (issuer) check
- [x] sub (subject) check
- [x] aud (audience) check
- [x] exp (expiration time) check
- [x] nbf (not before time) check
- [x] iat (issued at) check

## Usage

Put this into your `Cargo.toml`:

```toml
[dependencies]
rustwt = "1.0.0"
```

And this in your crate root:

```rust
extern crate rusty_jwt;

use rustwt::{Header, Payload, Algorithm, encode, decode};
```

## License

Apache 2.0

## Tests

```shell
cargo test
```
