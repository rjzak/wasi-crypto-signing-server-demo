This is a super simple application which uses [Wasi-Crypto](https://github.com/WebAssembly/wasi-crypto) to sign an arbitrary binary blob POSTed to `/`.

## Prerequisite
* Binaries for [Enarx](https://github.com/enarx/enarx) and [Wasmtime](https://github.com/bytecodealliance/wasmtime) compiled with Wasi-Crypto support for `x86_64-unknown-gnu` are available here: https://github.com/rjzak/wasi-crypto-example/releases/tag/v0.0.1.

## Compiling:
* `rustup target add wasm32-wasi`, first time only
* `cargo build`

## Running:
Be sure to use the binaries from the links above, or compile them from source.
* Enarx: `CARGO_TARGET_WASM32_WASI_RUNNER="enarx run --wasmcfgfile ../Enarx.toml"  cargo +nightly run --target wasm32-wasi`
* Wasmtime: `CARGO_TARGET_WASM32_WASI_RUNNER="wasmtime run --tcplisten 127.0.0.1:8443 --env FD_COUNT=1"  cargo +nightly run --target wasm32-wasi`
* Place the downloaded binaries, or simlinks to them, in the project, and simply run `cargo run` or `cargo test`. See `.cargo/config` for details.