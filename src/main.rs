extern crate core;

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::wasi::io::FromRawFd;
use tokio::sync::Mutex;
use wasi_crypto_guest::signatures::SignatureKeyPair;

static KEYS: Lazy<Mutex<State>> = Lazy::new(|| Mutex::new(State::default()));

static ALGS: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert("ES256", "ECDSA_P256_SHA256");
    map.insert("ES384", "ECDSA_P384_SHA384");
    map
});

#[derive(Default)]
struct State(HashMap<String, SignatureKeyPair>);

impl State {
    pub fn keypair(&mut self, algo: &str) -> Result<&SignatureKeyPair, StatusCode> {
        if self.0.contains_key(algo) {
            Ok(self.0.get(algo).unwrap())
        } else {
            let alg = ALGS.get(algo).ok_or(StatusCode::NOT_FOUND)?;
            let key = SignatureKeyPair::generate(alg).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(self.0.entry(algo.into()).or_insert(key))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
    std_listener.set_nonblocking(true).unwrap();
    axum::Server::from_tcp(std_listener)
        .unwrap()
        .serve(app().into_make_service())
        .await?;

    Ok(())
}

fn app() -> Router {
    Router::new()
        .route("/:algo", post(do_signing))
        .route("/:algo", get(get_key))
}

async fn get_key(Path(algo): Path<String>) -> Result<Json<Jwk>, StatusCode> {
    let mut lock = KEYS.lock().await;
    let key = lock.keypair(&algo)?;

    // Assumed: SEC1 Works
    let sec1 = key
        .publickey()
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .sec()
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Assumed: SEC1 Uncompressed
    assert_eq!(sec1[0], 4);
    let sec1 = &sec1[1..];

    Ok(Json(Jwk {
        kty: "EC".into(),
        crv: match algo.as_str() {
            "ES256" => "P-256",
            "ES384" => "P-384",
            _ => return Err(StatusCode::NOT_FOUND),
        }
        .into(),
        x: base64::encode_config(&sec1[..sec1.len() / 2], base64::URL_SAFE_NO_PAD),
        y: base64::encode_config(&sec1[sec1.len() / 2..], base64::URL_SAFE_NO_PAD),
    }))
}

async fn do_signing(Path(algo): Path<String>, body: Bytes) -> Result<String, StatusCode> {
    let head = format!("{{alg:\"{}\"}}", algo);
    let hdr = base64::encode_config(head, base64::URL_SAFE_NO_PAD);
    let b64 = base64::encode_config(body, base64::URL_SAFE_NO_PAD);
    let env = format!("{}.{}", hdr, b64);

    let mut lock = KEYS.lock().await;
    let key = lock.keypair(&algo)?;

    let sig = key.sign(&env).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Assumed: R (big endian) || S (big endian)
    let raw = sig.raw().or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let end = base64::encode_config(raw, base64::URL_SAFE_NO_PAD);

    Ok(format!("{}.{}", env, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::request::Request;
    use tower::ServiceExt; // for `app.oneshot()`

    const RANDOM_SIZE: usize = 2048;

    #[tokio::test]
    async fn test_signing_works() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        assert_eq!(random_bytes.len(), RANDOM_SIZE);

        let server = SigningServer::new().unwrap();
        let sig = server.sign(&random_bytes).unwrap();
        let signature_raw = sig.raw().unwrap();
        assert_eq!(signature_raw.len(), 96);
    }

    #[tokio::test]
    async fn test_get_pub_key_valid_from_bytes() {
        let server = SigningServer::new().unwrap();
        let pubkey = server.pub_key_raw().unwrap();
        assert_eq!(pubkey.len(), 49);

        SignaturePublicKey::from_raw(&CRYPTO_ALGO, pubkey).unwrap();
    }

    #[tokio::test]
    async fn test_server_process() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        assert_eq!(random_bytes.len(), RANDOM_SIZE);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(random_bytes.clone()))
            .unwrap();

        let server = SigningServer::new().unwrap();
        let pubkey = server.pub_key().unwrap();
        let response = app(server).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let signature = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let signature_obj = Signature::from_raw(&CRYPTO_ALGO, signature).unwrap();
        pubkey
            .signature_verify(random_bytes, &signature_obj)
            .unwrap();
    }

    #[tokio::test]
    async fn test_server_fail() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        assert_eq!(random_bytes.len(), RANDOM_SIZE);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(random_bytes))
            .unwrap();

        let server = SigningServer::new().unwrap();
        let pubkey = server.pub_key().unwrap();
        let response = app(server).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Different random bytes so the signature verification should fail
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        let signature = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let signature_obj = Signature::from_raw(&CRYPTO_ALGO, signature).unwrap();
        match pubkey.signature_verify(random_bytes, &signature_obj) {
            Ok(_) => {
                assert!(false, "this should fail!")
            }
            Err(_) => {} // Should be an error!
        }
    }
}
