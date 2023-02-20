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

const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:7676";
// const RP_ID: &str = "passkey-demo.edgecompute.app";
// const RP_ORIGIN: &str = "https://passkey-demo.edgecompute.app";

// const CUSTOM_ENGINE: engine::GeneralPurpose =
//     engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

#[derive(serde::Deserialize, serde::Serialize)]
struct Form {
    username: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct RegResp {
    username: String,
    response: RegisterPublicKeyCredential,
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    let rp_origin = Url::parse(RP_ORIGIN).expect("Invalid relying party URL.");
    let builder =
        WebauthnBuilder::new(RP_ID, &rp_origin).expect("Invalid WebAuthn configuration.");
    let webauthn = builder.build().expect("Invalid WebAuthn configuration.");

    // Username to UUID mapping.
    let mut users = ObjectStore::open("users")?.unwrap();
    // UUID to registration (& auth, in the future) state mapping.
    let mut state = ObjectStore::open("state")?.unwrap();
    // UUID to passkeys mapping.
    let mut keys = ObjectStore::open("keys")?.unwrap();

    match (req.get_method(), req.get_path()) {
        // Base HTML.
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
        // Registration - start.
        (&Method::POST, "/registration/start") => {
            let reg = req.take_body_json::<Form>().unwrap();
            // 1. Presented credentials may *only* provide the uuid, and not the username!
            // 2. If the user has any other credentials, we need to exclude these from being re-registered.
            let (user_id, exclude_credentials) = match users.lookup_str(&reg.username) {
                Ok(Some(id)) => {
                    println!("Existing uid for {} is {}", reg.username, id);
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
                        .insert(&reg.username, id.to_string())
                        .expect("Failed to register new UUID.");
                    (id, None)
                }
            };

            let (creation_challenge_response, reg_state) = webauthn
                .start_passkey_registration(
                    user_id,
                    &reg.username,
                    &reg.username,
                    exclude_credentials,
                )
                .expect("Failed to start registration.");

            // Safe to store the reg_state into the object store since it is not client controlled.
            // If this was a cookie store, this would be UNSAFE (open to replay attacks).
            state
                .insert(&user_id.to_string(), serde_json::to_string(&reg_state)?)
                .expect("Failed to store registration state.");

            println!("DEBUG reg_state {:?}", reg_state);

            Ok(Response::from_status(StatusCode::OK)
                .with_body_json(&creation_challenge_response)?)
        }
        // Registration - finish (verify).
        (&Method::POST, "/registration/finish") => {
            let reg = req.take_body_json::<RegResp>().unwrap();

            println!("DEBUG reg.response {:?}", reg.response);
            
            // Retrieve UUID for the username.
            let user_id = users.lookup_str(&reg.username)?.unwrap();
            // Retrieve and deserialize registration state for the UUID.
            let rs = state.lookup_str(&user_id).expect("Session corrupted.");
            let reg_state = serde_json::from_str::<PasskeyRegistration>(&rs.unwrap())?;
            
            println!("DEBUG reg_state {:?}", reg_state);

            let passkey_registration = webauthn
                .finish_passkey_registration(&reg.response, &reg_state)
                .expect("Failed to finish registration.");

            // TODO: This needs to be an array of keys.
            keys.insert(&user_id, serde_json::to_string(&passkey_registration)?)
                .expect("Failed to store passkey.");

            Ok(Response::from_status(StatusCode::OK))
        }
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
