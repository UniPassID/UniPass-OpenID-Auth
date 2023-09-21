# UniPass-OpenID-Auth

## Usage

This repository is used to generate verification data for OpenID IdTokens for on-chain validation. 

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

If you only need direct verification without privacy perserving, you need to place a valid id_token in `build/id_token.txt`, then run `cargo run --release open-id-args` and find the output at `build/id_token.output`.

If you want to hide user identifiers using zero-knowledge proofs, first run `cargo run --release gen-params` to generate parameters, and then run `cargo run --release gen-keys` to generate the public keys used for zero-knowledge proof generation. To perform this step, you need to place a valid id_token in `build/id_token.txt`. Then, run `cargo run --release open-id-zk-args --pepper 0x...` to generate the necessary output, where 'pepper' is a 32-byte long hex expression used to hide 'sub'. You can find the required output in `build/zkConfigs`.json and `build/id_token_zk.output`.


Then, configure all the outputs as environment variables according to the [OpenID-Auth-Contracts](https://github.com/UniPassID/OpenID-Auth-Contracts)'s specified rules , and you can verify the on-chain Id Token validation functionality.


## Design

### Id Token

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

### Direct OpenID Verification

By using `iss` and `kid`, you can uniquely bind a public key and verify validity of the token using that public key and signature. 

Then, use `iat`, `exp`, and the current block.timestamp to validate that the token is in a valid time. 

Obtain the `nonce` and `sub` for further verification. Typically, the nonce contains information indicating the user's intent, and `sub`, when combined with `iss`, uniquely binds an OpenID key.

So, the verification process is as follows:
+ First, use `iss` and `kid` to locate the specified public key within the authorized set of public keys. Then, using that public key and the signature contained within the Id Token, perform signature verification on the `hash(BASE64URL(UTF8(Header)) || '.' || BASE64URL(Payload))`. If the verification is successful, proceed with other checks; otherwise, the verification fails.
+ Then, use iat and exp to ensure that the currently used Id Token is still within its validity period.
+ Then, use `aud` and `iss` to verify that the token was requested by an authorized entity.
+ Finally, extract `nonce` and `sub` from the payload, and verify whether `iss + sub` corresponds to the user's recorded OpenID key. Additionally, ensure that the nonce corresponds to the user's intent, such as storing the hash of a transaction(include tx nonce for replay protection).

### Privacy-Perserving OpenID Verification

If you require privacy protection, meaning you need to hide the user's sub on-chain, then you should use zero-knowledge proofs for information hiding. The circuit should adhere to the following logic verification:

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

So, the verification process is as follows:

Where `id_token_hash` and `sub_peeper_hash` will be provided directly and constrained in their relationship with `header` and `payload_pub_match` within `public_input`. By using `id_token_hash`, `kid` from the header, `iss` from `payload_pub_match`, and the `signature`, you can verify the signature validity of this token.

Using `iat` and `exp` from `payload_pubmatch`, you can verify whether the token is within its valid time period.

Then, use the `aud` extracted from `payload_pub_match` along with `iss` to verify that the token was requested by an authorized entity.

Using `public_input` and the `proof` to validate the effectiveness of the zero-knowledge proof.

Using `sub_papper_hash` and `iss`, you can bind to a user's OpenID key, and by using the nonce extracted from `payload_pub_match`, you can associate it with the user's intent.


## FAQs

Who can determine the on-chain public keys corresponding to iss and kid? Who can add authorized public keys?

Ans: This problem is challenging to resolve completely. Firstly, we can utilize a specific oracle network to manage the update of authorized public keys, and these updates would only become effective after a certain time lock, thus preventing malicious public keys from being added to the authorized public key set.