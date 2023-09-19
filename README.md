# UniPass-OpenID-Auth

This repository is used to generate verification data for OpenID IdTokens for on-chain validation. 

If you only need direct verification without privacy perserving, you need to place a valid id_token in `build/id_token.txt`, then run `cargo run --release open-id-args` and find the input at `build/id_token.output`.

If you want to hide user identifiers using zero-knowledge proofs, first run `cargo run --release gen-params` to generate parameters, and then run `cargo run --release gen-keys` to generate the public keys used for zero-knowledge proof generation. To perform this step, you need to place a valid id_token in `build/id_token.txt`. Then, run `cargo run --release open-id-zk-args --pepper 0x...` to generate the necessary output, where 'pepper' is a 32-byte long hex expression used to hide 'sub'. You can find the required output in `build/zkConfigs`.json and `build/id_token_zk.output`.

```
Usage: unipass_openid_auth <COMMAND>

Commands:
  gen-params       Generate a setup parameter (not for production)
  gen-keys         Generate proving keys and verifying keys
  prove            
  verify           
  open-id-args     
  open-id-zk-args  
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Design

An OpenID IdToken is primarily composed of three parts: Header, Payload, and Signature.

The IdToken is a JWT with the following format:

```
Header.Payload.Signature
```

The calculation logic is as follows:

```
BASE64URL(UTF8(Header)) || '.' ||
BASE64URL(Payload) || '.' ||
BASE64URL(Signature)
```

Example: `eyJhbGciOiJSUzI1NiIsImtpZCI6IjdjMGI2OTEzZmUxMzgyMGEzMzMzOTlhY2U0MjZlNzA1MzVhOWEwYmYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwMjg3ODQ1NTY1MDY4MTY0NDEiLCJhdF9oYXNoIjoidkp2ZXRrUmR4eGVtTEw3NjVfZDJYdyIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwibmJmIjoxNjk0Njc4MTkzLCJpYXQiOjE2OTQ2Nzg0OTMsImV4cCI6MTY5NDY4MjA5MywianRpIjoiMTk1ZjZiN2FlMTgxMmFlNGFjZDQ0YmUwMzE1YjQ1NDdiOTkyMDIzMyJ9.BoC3b7RDy7JTPH2UqrDbMCaQgaTjwr5GLwyVVZ6Unhn32mVI-EST7uOirXIb4h2W5e5A8Uw0bSkXy7tB3ByCV5QNyvR8d7dm0yKo53jGywGgvKtrDRrDHXdOC7vmG_y88I5keKSOsYk6Yzo7aHxoynZggal24oinqBCDdkkXw2P6v5UuJIK1B2DJAsbzsBhjvRvlgMJpTraTz3b4Wfp7KCZQfr1J6gRw9-9heWJUmwbbXdOsSGxmGR9KNUH_cmwPXHvG8WUG0ENn5WNuhBdbz1lXT3FbOkG1MSNZ7I91vfsnZMbr71Pawc36lNBq_TfU4UNhJ8i1dRH-vii7SlyhpQ`



The header content is as follows:

```json
{"alg":"RS256","kid":"7c0b6913fe13820a333399ace426e70535a9a0bf","typ":"JWT"}
```

Where:

- `alg` denotes the signing algorithm used for the IdToken.
- `kid` specifies which key was used to sign the IdToken.

The payload content is as follows:

```json
{"iss":"https://accounts.google.com","azp":"407408718192.apps.googleusercontent.com","aud":"407408718192.apps.googleusercontent.com","sub":"105028784556506816441","at_hash":"vJvetkRdxxemLL765_d2Xw","nonce":"n-0S6_WzA2Mj","nbf":1694678193,"iat":1694678493,"exp":1694682093,"jti":"195f6b7ae1812ae4acd44be0315b4547b9920233"}
```

Key attributes include:

- `iss`: The issuer or signer of the token.
- `azp`: Who the token was issued to.
- `aud`: The audience of the token.
- `sub`: The subject, which represents the principal making the request.
- `nonce`: A string value used to associate a Client session with an ID Token and mitigate replay attacks.
- `nbf`: Unix epoch time when the token is not valid before.
- `iat`: Unix epoch time when the token was issued.
- `exp`: Unix epoch time when the token expires.
- `jti`: JWT ID.

By using `iss` and `kid`, you can uniquely bind a public key and verify validity of the token using that public key and signature. 

Then, use `iat`, `exp`, and the current timestamp to validate that the token is in a valid time. 

Obtain the `nonce` and hash of `sub` for further verification. Typically, the nonce contains information indicating the user's intent, and `sub`, when combined with `iss`, uniquely binds an OpenID key.

If privacy protection is required, you need to use the following zk-circuit design:

- Calculate id_token_hash.
- Calculate sub_pepper_hash using sub and pepper.
- Encode payload_raw to payload_base64.
- Calculate payload_pub_match_hash.
- Encode header_raw to header_base64.
- Calculate header_raw_hash.
- Prove that payload_base64 is a substring of id_token using id_token_hash as the mask.
- Prove that header_base64 is a substring of id_token using header_hash as the mask.
- Prove that sub is a substring of payload_raw using sub_pepper_hash as the mask.
- Calculate public_input, which is sha256(id_token_hash|sub_pepper_hash|header_hash|payload_pubmatch_hash|bit_location_id_token_1|bit_location_payload_base64|bit_location_id_token_2|bit_location_header_base64|bit_location_payload_raw|bit_location_email_addr).

To verify, use `id_token_hash` for signature verification, `payload_pub_match` (with sensitive information removed) for other checks like timestamps, nonce, etc., and also verify the correctness of the zero-knowledge proof and the correctness of constructing public_input.