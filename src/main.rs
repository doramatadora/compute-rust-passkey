use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, ObjectStore, Request, Response};
use webauthn_rs::prelude::*;

const INDEX_HTML: &str = include_str!("assets/index.html");
const STYLE_CSS: &str = include_str!("assets/style.css");
const WEBAUTHN_JS: &[u8] = include_bytes!("assets/webauthn.js");

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:7676").expect("Invalid URL");
    let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let webauthn = builder.build().expect("Invalid configuration");

    // Initiate a basic registration flow to enroll a cryptographic authenticator
    let (ccr, skr) = webauthn
        .start_passkey_registration(Uuid::new_v4(), "claire", "Claire", None)
        .expect("Failed to start registration.");

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

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
