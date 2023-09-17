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