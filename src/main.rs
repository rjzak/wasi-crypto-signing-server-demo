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
    use wasi_crypto_guest::signatures::{Signature, SignaturePublicKey};

    const RANDOM_SIZE: usize = 2048;
    const TEST_CRYPTO_ALGO:&'static str = "ES384";

    #[tokio::test]
    async fn test_get_pub_key_valid_from_bytes() {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/{}", TEST_CRYPTO_ALGO))
            .body(Body::from(""))
            .unwrap();

        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let signature_response = hyper::body::to_bytes(response.into_body()).await.unwrap().to_vec();
        let jwk_obj:Jwk = serde_json::from_slice(&signature_response).unwrap();

        let mut sec_bytes = Vec::new();
        sec_bytes.push(4u8);
        let mut x = base64::decode_config(&jwk_obj.x.as_bytes(), base64::URL_SAFE_NO_PAD).unwrap();
        sec_bytes.append(&mut x);
        let mut y = base64::decode_config(&jwk_obj.y.as_bytes(), base64::URL_SAFE_NO_PAD).unwrap();
        sec_bytes.append(&mut y);

        SignaturePublicKey::from_sec(ALGS.get(TEST_CRYPTO_ALGO).unwrap(), sec_bytes).unwrap();
    }

    #[tokio::test]
    async fn test_server_process() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        assert_eq!(random_bytes.len(), RANDOM_SIZE);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}", TEST_CRYPTO_ALGO))
            .body(Body::from(random_bytes.clone()))
            .unwrap();

        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let signature_response = hyper::body::to_bytes(response.into_body()).await.unwrap().to_vec();
        let mut signature = signature_response.split(|item| *item == b'.');
        signature.next(); // first item is base64("algo:<the_algo>")
        signature.next(); // second item is base64("<the_data>")
        let signature_decoded = base64::decode_config(signature.next().unwrap(), base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(signature_decoded.len(), 96);
        let signature_obj = Signature::from_raw(ALGS.get(TEST_CRYPTO_ALGO).unwrap(), signature_decoded).unwrap();
        let mut lock = KEYS.lock().await;
        let keypair = lock.keypair(TEST_CRYPTO_ALGO).unwrap();
        let pubkey = keypair.publickey().unwrap();

        let hdr = base64::encode_config(format!("{{alg:\"{}\"}}", TEST_CRYPTO_ALGO), base64::URL_SAFE_NO_PAD);
        let b64 = base64::encode_config(random_bytes, base64::URL_SAFE_NO_PAD);
        let env = format!("{}.{}", hdr, b64);

        pubkey.signature_verify(env.as_bytes(), &signature_obj).unwrap();
    }

    #[tokio::test]
    async fn test_server_fail() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        assert_eq!(random_bytes.len(), RANDOM_SIZE);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}", TEST_CRYPTO_ALGO))
            .body(Body::from(random_bytes.clone()))
            .unwrap();

        let response = app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let signature_response = hyper::body::to_bytes(response.into_body()).await.unwrap().to_vec();
        let mut signature = signature_response.split(|item| *item == b'.');
        signature.next(); // first item is base64("algo:<the_algo>")
        signature.next(); // second item is base64("<the_data>")
        let signature_decoded = base64::decode_config(signature.next().unwrap(), base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(signature_decoded.len(), 96);
        let signature_obj = Signature::from_raw(ALGS.get(TEST_CRYPTO_ALGO).unwrap(), signature_decoded).unwrap();
        let mut lock = KEYS.lock().await;
        let keypair = lock.keypair(TEST_CRYPTO_ALGO).unwrap();
        let pubkey = keypair.publickey().unwrap();

        let hdr = base64::encode_config(format!("{{alg:\"{}\"}}", TEST_CRYPTO_ALGO), base64::URL_SAFE_NO_PAD);
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| rand::random::<u8>()).collect();
        let b64 = base64::encode_config(random_bytes, base64::URL_SAFE_NO_PAD);
        let env = format!("{}.{}", hdr, b64);

        match pubkey.signature_verify(env.as_bytes(), &signature_obj) {
            Ok(_) => assert!(false),
            Err(_) => {}, // should fail
        }
    }
}
