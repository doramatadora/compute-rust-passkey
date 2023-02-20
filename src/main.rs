use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, ObjectStore, Request, Response};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
// use base64::{
//     alphabet,
//     engine::{self, general_purpose},
//     Engine as _,
// };

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const WEBAUTHN_JS: &[u8] = include_bytes!("assets/webauthn.js");

// const CUSTOM_ENGINE: engine::GeneralPurpose =
//     engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

#[derive(serde::Deserialize, serde::Serialize)]
struct Form {
    username: String,
}

// #[derive(serde::Deserialize, serde::Serialize)]
// struct UserState {
//     id: Uuid,
//     reg_state: Option<PasskeyRegistration>,
// }

#[derive(Deserialize, Serialize)]
struct UserKeys {
    keys: Vec<Passkey>,
}

#[derive(Deserialize, Serialize, Debug)]
struct RegResp {
    username: String,
    response: RegisterPublicKeyCredential,
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:7676").expect("Invalid relying party URL.");
    let mut builder =
        WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid WebAuthn configuration.");
    let webauthn = builder.build().expect("Invalid WebAuthn configuration.");

    // Username to UUID mapping
    let mut users = ObjectStore::open("users")?.unwrap();
    // UUID to registration state mapping
    let mut state = ObjectStore::open("state")?.unwrap();
    // UUID to passkeys mapping
    let mut keys = ObjectStore::open("keys")?.unwrap();

    match (req.get_method(), req.get_path()) {
        (&Method::GET, "/robots.txt") => Ok(Response::from_status(StatusCode::OK)
            .with_body_text_plain("User-agent: *\nDisallow: /\n")),
        (&Method::GET, "/favicon.ico") => Ok(Response::from_status(StatusCode::NOT_FOUND)),
        (&Method::GET, "/style.css") => Ok(Response::from_status(StatusCode::OK)
            .with_content_type(fastly::mime::TEXT_CSS)
            .with_body(STYLE_CSS)),
        (&Method::GET, "/auth.js") => Ok(Response::from_status(StatusCode::OK)
            .with_content_type(mime::APPLICATION_JAVASCRIPT_UTF_8)
            .with_body_octet_stream(WEBAUTHN_JS)),
        (&Method::GET, "/") => {
            Ok(Response::from_status(StatusCode::OK).with_body_text_html(INDEX_HTML))
        }
        (&Method::POST, "/registration/options") => {
            let opts = req.take_body_json::<Form>().unwrap();
            // 1. Presented credentials may *only* provide the uuid, and not the username!
            // 2. If the user has any other credentials, we need to exclude these from being re-registered.
            let (user_id, exclude_credentials) = match users.lookup_str(&opts.username) {
                Ok(Some(id)) => {
                    println!("Existing uid for {} is {}", opts.username, id);
                    match keys.lookup_str(&id) {
                        Ok(Some(k)) => {
                            let existing: Vec<Passkey> = serde_json::from_str(&k).unwrap();
                            (
                                Uuid::try_parse(&id)?,
                                Some(
                                    existing
                                        .iter()
                                        .map(|sk| sk.cred_id().clone())
                                        .collect::<Vec<CredentialID>>(),
                                ),
                            )
                        }
                        _ => (Uuid::try_parse(&id)?, None),
                    }
                }
                _ => {
                    let id = Uuid::new_v4();
                    users
                        .insert(&opts.username, id.to_string())
                        .expect("Failed to register new UUID.");
                    (id, None)
                }
            };

            // Initiate a basic registration flow to enroll a cryptographic authenticator
            let (creation_challenge_response, reg_state) = webauthn
                .start_passkey_registration(
                    user_id,
                    &opts.username,
                    &opts.username,
                    exclude_credentials,
                )
                .expect("Failed to start registration.");

            // Safe to store the reg_state into the object store since it is not client controlled.
            // If this was a cookie store, this would be UNSAFE (open to replay attacks).
            state
                .insert(&user_id.to_string(), serde_json::to_string(&reg_state)?)
                .expect("Failed to store registration state.");

            println!(
                "user_id: {}, name {}, skr {:?}, ccr {:?}",
                user_id, opts.username, reg_state, creation_challenge_response
            );

            Ok(Response::from_status(StatusCode::OK)
                .with_body_json(&creation_challenge_response)?)
        }
        (&Method::POST, "/registration/verification") => {
            let reg = req.take_body_json::<RegResp>().unwrap();

            // Initiate a basic registration flow to enroll a cryptographic authenticator
            // let (sk) = webauthn
            //     .finish_passkey_registration(&reg.response, &reg_state)
            //     .expect("Failed to start registration.");

            println!("registration verification");
            println!("body {:?}", reg);
            // webauthn.finish_passkey_registration(reg, state);
            Ok(Response::from_status(StatusCode::OK))
        }
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}