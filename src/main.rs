extern crate core;

use anyhow::anyhow;
use std::os::wasi::io::FromRawFd;
use std::sync::Arc;
use wasi_crypto_guest::signatures::{Signature, SignatureKeyPair, SignaturePublicKey};
use axum::{body::Bytes, http::StatusCode, routing::{get, post}, Extension, Router};

const CRYPTO_ALGO:&'static str = "ECDSA_P384_SHA384";

#[derive(Debug)]
struct SigningServer {
    pub keypair: SignatureKeyPair,
}

impl SigningServer {
    fn new() -> anyhow::Result<Self> {
        let keypair = match SignatureKeyPair::generate(&CRYPTO_ALGO) {
            Ok(k) => k,
            Err(e) => {
                return Err(anyhow!("error generating keypair {:?}", e))
            }
        };
        Ok(SigningServer {
            keypair
        })
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Signature> {
        match self.keypair.sign(data) {
            Ok(s) => Ok(s),
            Err(e) => return Err(anyhow!("error signing data {:?}", e))
        }
    }

    fn pub_key(&self) -> anyhow::Result<SignaturePublicKey> {
        match self.keypair.publickey() {
            Ok(s) => Ok(s),
            Err(e) => return Err(anyhow!("error retrieving public key {:?}", e))
        }
    }

    fn pub_key_raw(&self) -> anyhow::Result<Vec<u8>> {
        match self.pub_key() {
            Ok(k) => match k.raw() {
                Ok(r) => Ok(r),
                Err(e) => return Err(anyhow!("error retrieving public key {:?}", e))
            }
            Err(e) => Err(e),
        }
    }

    #[allow(dead_code)]
    fn validate_signature(&self, sig: Vec<u8>, data: Vec<u8>) -> bool {
        let signature_obj = match Signature::from_raw(&CRYPTO_ALGO, sig) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Cannot load signature: {:?}", e);
                return false;
            }
        };

        match self.pub_key().unwrap().signature_verify(data, &signature_obj) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let server = SigningServer::new()?;
    println!("Keypair generated.");

    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
    std_listener.set_nonblocking(true).unwrap();
    axum::Server::from_tcp(std_listener)
        .unwrap()
        .serve(app(server).into_make_service())
        .await?;

    Ok(())
}

fn app(state: SigningServer) -> Router {
    Router::new()
        .route("/", post(do_signing))
        .route("/", get(get_key))
        .route("/pem", post(do_signing_pem))
        .route("/pem", get(get_key_pem))
        .layer(Extension(Arc::new(state)))
}

async fn get_key(Extension(state): Extension<Arc<SigningServer>>) -> Result<Vec<u8>, StatusCode> {
    match state.pub_key_raw() {
        Ok(k) => {
          Ok(k)
        },
        Err(e) => {
            eprintln!("Error getting key as bytes: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_key_pem(Extension(state): Extension<Arc<SigningServer>>) -> Result<Vec<u8>, StatusCode> {
    // Untested
    match state.keypair.pkcs8() {
        Ok(k) => {
            Ok(k)
        },
        Err(e) => {
            eprintln!("Error getting key as pem: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn do_signing(
    body: Bytes,
    Extension(state): Extension<Arc<SigningServer>>,
) -> Result<Vec<u8>, StatusCode> {
    let sig = state.sign(&body).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let signature_raw = match sig.raw() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error getting signature bytes: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(signature_raw)
}

async fn do_signing_pem(
    body: Bytes,
    Extension(state): Extension<Arc<SigningServer>>,
) -> Result<Vec<u8>, StatusCode> {
    // Untested
    let sig = state.sign(&body).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let signature_raw = match sig.der() {
        Ok(s) => {
            base64::encode(s).into()
        },
        Err(e) => {
            eprintln!("Error getting signature bytes: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(signature_raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::request::Request;
    use axum::body::Body;
    use tower::ServiceExt; // for `app.oneshot()`

    const RANDOM_SIZE:usize = 2048;

    #[tokio::test]
    async fn test_signing_works() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| { rand::random::<u8>() }).collect();
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
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| { rand::random::<u8>() }).collect();
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
        pubkey.signature_verify(random_bytes, &signature_obj).unwrap();
    }

    #[tokio::test]
    async fn test_server_fail() {
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| { rand::random::<u8>() }).collect();
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
        let random_bytes: Vec<u8> = (0..RANDOM_SIZE).map(|_| { rand::random::<u8>() }).collect();
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