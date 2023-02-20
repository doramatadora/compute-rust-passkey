# Passkeys on Compute@Edge

You want to set the `OPENSSL_DIR` env variable to point to `openssl-wasm/precompiled`, and `OPENSSL_STATIC` to `1`.

```sh
> export OPENSSL_STATIC=1
> export OPENSSL_DIR=/Users/dmilitaru/experiments/compute-rust-passkey/openssl-wasm/precompiled/
```

Test via `http://localhost:7676/` rather than `http://127.0.0.1:7676` – `127.0.0.1` is not a valid RP domain.