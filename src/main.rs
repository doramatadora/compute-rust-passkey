use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, KVStore, Request, Response};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const AUTH_JS: &[u8] = include_bytes!("assets/auth.js");

// const RP_ID: &str = "localhost";
// const RP_ORIGIN: &str = "http://localhost:7676";
const RP_ID: &str = "passkeys.edgecompute.app";
const RP_ORIGIN: &str = "https://passkeys.edgecompute.app";

#[derive(serde::Deserialize, serde::Serialize)]
struct Form {
    username: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct RegResp {
    username: String,
    response: RegisterPublicKeyCredential,
}

#[derive(Deserialize, Serialize, Debug)]
struct AuthResp {
    username: String,
    response: PublicKeyCredential,
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Initialize WebAuthn, which has no mutable inner state.
    let rp_origin = Url::parse(RP_ORIGIN).expect("Invalid relying party URL.");
    let builder = WebauthnBuilder::new(RP_ID, &rp_origin).expect("Invalid WebAuthn configuration.");
    let webauthn = builder.build().expect("Invalid WebAuthn configuration.");

    // Username to UUID mapping.
    let mut users = KVStore::open("users")?.unwrap();
    // UUID to registration (& auth, in the future) state mapping.
    let mut state = KVStore::open("state")?.unwrap();
    // UUID to passkeys mapping.
    let mut keys = KVStore::open("keys")?.unwrap();

    match (req.get_method(), req.get_path()) {
        // Frontend stuff.
        (&Method::GET, "/robots.txt") => Ok(Response::from_status(StatusCode::OK)
            .with_body_text_plain("User-agent: *\nDisallow: /\n")),
        (&Method::GET, "/favicon.ico") => Ok(Response::from_status(StatusCode::NOT_FOUND)),
        (&Method::GET, "/style.css") => Ok(Response::from_status(StatusCode::OK)
            .with_content_type(fastly::mime::TEXT_CSS)
            .with_body(STYLE_CSS)),
        (&Method::GET, "/auth.js") => Ok(Response::from_status(StatusCode::OK)
            .with_content_type(mime::APPLICATION_JAVASCRIPT_UTF_8)
            .with_body_octet_stream(AUTH_JS)),
        (&Method::GET, "/") => {
            Ok(Response::from_status(StatusCode::OK).with_body_text_html(INDEX_HTML))
        }

        // Registration - start.
        // Responding by providing the challenge to the browser.
        (&Method::POST, "/registration/start") => {
            println!("DEBUG start registration");

            let form = req.take_body_json::<Form>().unwrap();

            // 1. Presented credentials may *only* provide the uuid, and not the username!
            // 2. If the user has any other credentials, we need to exclude these from being re-registered.
            let (user_id, exclude_credentials) = match users.lookup_str(&form.username) {
                Ok(Some(id)) => {
                    println!("Existing uid for {} is {}", form.username, id);
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
                        .insert(&form.username, id.to_string())
                        .expect("Failed to register new UUID.");
                    (id, None)
                }
            };

            let (creation_challenge_response, reg_state) = webauthn
                .start_passkey_registration(
                    user_id,
                    &form.username,
                    &form.username,
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
        // The browser has completed its steps and the user has created a public key
        // on their device. Now we have the registration options sent to us, and we need
        // to verify these and persist them.
        (&Method::POST, "/registration/finish") => {
            println!("DEBUG finish registration");

            let reg = req.take_body_json::<RegResp>().unwrap();

            println!("DEBUG reg.response {:?}", reg.response);

            // Retrieve UUID for the username.
            let user_id = users
                .lookup_str(&reg.username)
                .expect("User not found")
                .unwrap();

            // Retrieve and deserialize registration state for the UUID.
            let st = state
                .lookup_str(&user_id)
                .expect("Couldn't retrieve registration state.")
                .unwrap();
            let reg_state =
                serde_json::from_str::<PasskeyRegistration>(&st).expect("Session corrupted.");

            println!("DEBUG reg_state {:?}", reg_state);

            let passkey_registration = webauthn
                .finish_passkey_registration(&reg.response, &reg_state)
                .expect("Failed to finish registration.");
            
            // Get existing keys for the user, if any.
            let credentials = match keys.lookup_str(&user_id) {
                Ok(Some(creds)) => creds,
                _ => "[]".to_owned(),
            };

            let mut existing_keys = serde_json::from_str::<Vec<Passkey>>(&credentials).expect("Credentials corrupted.");
            existing_keys.push(passkey_registration.clone());

            keys.insert(&user_id, serde_json::to_string(&existing_keys)?)
                .expect("Failed to store passkey.");

            Ok(Response::from_status(StatusCode::OK))
        }

        // Authentication - start.
        // Now that our public key has been registered, we can authenticate a user and verify
        // that they are the holder of that security token. We need to provide a challenge.
        (&Method::POST, "/authentication/start") => {
            println!("DEBUG start authentication");

            let form = req.take_body_json::<Form>().unwrap();

            // Retrieve UUID for the username.
            let user_id = users
                .lookup_str(&form.username)
                .expect("User not found")
                .unwrap();

            // Retrieve and deserialize the user's set of credentials.
            let credentials = keys
                .lookup_str(&user_id)
                .expect("Couldn't retrieve stored credentials.")
                .unwrap();
            println!("DEBUG credentials {:?}", credentials);
            let allow_credentials =
                serde_json::from_str::<Vec<Passkey>>(&credentials).expect("Credentials corrupted.");

            let (request_challenge_response, auth_state) = webauthn
                .start_passkey_authentication(&allow_credentials)
                .expect("Failed to start authentication.");

            println!("DEBUG auth_state {:?}", auth_state);

            println!("DEBUG request_challenge_response {:?}", request_challenge_response);

            // Safe to store the auth_state into the object store since it is not client controlled.
            // If this was a cookie store, this would be UNSAFE (open to replay attacks).
            state
                .insert(&user_id.to_string(), serde_json::to_string(&auth_state)?)
                .expect("Failed to store auth state.");

            Ok(
                Response::from_status(StatusCode::OK)
                    .with_body_json(&request_challenge_response)?,
            )
        }

        // Authentication - finish.
        // The browser has completed its part of the processing.
        // We need to verify that the response matches the stored auth_state.
        (&Method::POST, "/authentication/finish") => {
            println!("DEBUG finish authentication");

            let auth = req.take_body_json::<AuthResp>().unwrap();

            println!("DEBUG auth.response {:?}", auth.response);

            // Retrieve UUID for the username.
            let user_id = users
                .lookup_str(&auth.username)
                .expect("User not found")
                .unwrap();

            // Retrieve and deserialize auth state for the UUID.
            let st = state
                .lookup_str(&user_id)
                .expect("Couldn't retrieve auth state.")
                .unwrap();
            let auth_state =
                serde_json::from_str::<PasskeyAuthentication>(&st).expect("Session corrupted.");

            println!("DEBUG auth_state {:?}", auth_state);

            let auth_result = webauthn
                .finish_passkey_authentication(&auth.response, &auth_state)
                .expect("Failed to finish authentication.");

            // Retrieve and update the user's set of credentials.
            let credentials = keys
                .lookup_str(&user_id)
                .expect("Couldn't retrieve stored credentials.")
                .unwrap();
            let mut updated_credentials =
                serde_json::from_str::<Vec<Passkey>>(&credentials).expect("Credentials corrupted.");
            updated_credentials.iter_mut().for_each(|sk| {
                // This will only update the credential if it's matching the one used for auth.
                sk.update_credential(&auth_result);
            });
            // Save the updated credentials.
            keys.insert(&user_id, serde_json::to_string(&updated_credentials)?)
                .expect("Failed to update credentials.");

            Ok(Response::from_status(StatusCode::OK))
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
