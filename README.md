# Passwordless authentication at the network's edge

This is a proof-of-concept implementation of passwordless authentication at the network's edge, using [Passkeys](#what-are-passkeys) & WebAuthn. 

It's built in Rust, for Fastly's [Compute@Edge](https://www.fastly.com/products/edge-compute).

It uses [KV Store](https://www.fastly.com/blog/introducing-object-store-enabling-powerful-applications-at-the-edge), Fastly's [CRDT-based edge state](https://www.infoq.com/presentations/architecture-global-scale/) system to store both user data and short-lived authentication challenges (no cookies!).

## What are Passkeys? 

[Passkeys](https://passkeys.dev/) are a new type of login credential that allows you to log in to sites and services without having to enter a password – think biometric locks. 

Passkeys are a compelling [WebAuthn](https://webauthn.guide/#about-webauthn)-based alternative to the ubiquitous “password + 2nd-factor” authentication. Unlike low assurance 2nd factors like SMS, they're resistant to [push](https://blog.hypr.com/what-are-push-notification-attacks)-phishing, unique across every website, and are generated using cryptographically secure hardware.

Additionally, passkeys generated by the 3 main platform authenticator vendors (Apple, Google, and Microsoft) are automatically synced across a user's devices, by their cloud account.

## What is _this_?

Look at the far right side of this diagram:
![FIDO2: WebAuthn + CTAP diagram](https://fidoalliance.org/fido2-project/fido2-graphic-v2/)

Imagine building a high scale, globally distributed [FIDO2 authentication solution](https://fidoalliance.org/specifications/) — without having to manage the underlying infrastructure. The code is executed at the network's edge, close to your users.

## Try it yourself

> If you haven't got a Fastly account, get one [for free](https://www.fastly.com/signup/), and head on over to [developer.fastly.com](https://developer.fastly.com/learning/compute) for instructions on getting started with Compute@Edge. 
>
> You'll need to install the [Fastly CLI](https://developer.fastly.com/learning/compute#install-the-fastly-cli) and [Rust language tooling](https://developer.fastly.com/learning/compute#install-language-tooling).

First, rebuild [`openssl-wasm`](https://github.com/jedisct1/openssl-wasm) with `bn_ops` set to `THIRTY_TWO_BIT` (or build OpenSSL for the `wasm32-wasi` target with [another tool](https://github.com/WebAssembly/wasi-sdk) of your choosing). 

Next, set the `OPENSSL_DIR` env variable to point to your precompiled library root, and `OPENSSL_STATIC` to `1`, to statically link OpenSSL.

```sh
export OPENSSL_STATIC=1
export OPENSSL_DIR=$(pwd)/openssl-wasm/precompiled/
```

Run `fastly compute serve` to spin up a local development server and see the demo in action, or `fastly compute serve --watch` if you want to hot-reload any changes to the code.

Open `http://localhost:7676/` in your browser, rather than `http://127.0.0.1:7676` – `127.0.0.1` is not a valid [RP](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) domain.
