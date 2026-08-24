//! WASM bindings for `rpgmad-lib`, generated via `wasm-bindgen`.
//!
//! The reference `Decrypter` borrows its input buffer for the lifetime of the returned iterator, which doesn't
//! translate across the JS/WASM boundary (a call only lives for the duration of the call). So instead of mirroring
//! the borrowing API 1:1, this crate exposes two eager, allocating free functions - `decryptArchive` and
//! `encryptArchive` - that copy data in and out at the boundary, same as any other WASM binding would.

use rpgmad_lib::{ArchiveEntry as InnerArchiveEntry, Decrypter, Engine as InnerEngine, ExtractError};
use wasm_bindgen::prelude::*;

/// Target/source RPG Maker engine of an archive.
#[wasm_bindgen]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Engine {
    /// RPG Maker XP / VX (`.rgssad` / `.rgss2a`).
    Older = 1,
    /// RPG Maker VX Ace (`.rgss3a`).
    VXAce = 3,
}

impl From<Engine> for InnerEngine {
    fn from(engine: Engine) -> Self {
        match engine {
            Engine::Older => InnerEngine::Older,
            Engine::VXAce => InnerEngine::VXAce,
        }
    }
}

/// A single decrypted file extracted from an archive.
#[wasm_bindgen(getter_with_clone)]
pub struct ArchiveEntry {
    pub path: Vec<u8>,
    pub data: Vec<u8>,
}

#[wasm_bindgen]
impl ArchiveEntry {
    #[wasm_bindgen(constructor)]
    pub fn new(path: Vec<u8>, data: Vec<u8>) -> ArchiveEntry {
        ArchiveEntry { path, data }
    }
}

fn to_js_error(error: ExtractError) -> JsError {
    JsError::new(&error.to_string())
}

/// Decrypts an RPG Maker archive, returning its entries.
///
/// `archiveData` is consumed - the returned entries are independent, owned copies.
#[wasm_bindgen(js_name = decryptArchive)]
pub fn decrypt_archive(mut archive_data: Vec<u8>) -> Result<Vec<ArchiveEntry>, JsError> {
    let mut decrypter = Decrypter::new();
    let entries = decrypter.decrypt(&mut archive_data).map_err(to_js_error)?;

    Ok(entries
        .map(|entry| ArchiveEntry {
            path: entry.path.to_vec(),
            data: entry.data.to_vec(),
        })
        .collect())
}

/// Encrypts archive entries into a full archive buffer for the given engine.
#[wasm_bindgen(js_name = encryptArchive)]
pub fn encrypt_archive(entries: Vec<ArchiveEntry>, engine: Engine) -> Vec<u8> {
    let inner_entries: Vec<InnerArchiveEntry> = entries
        .iter()
        .map(|entry| InnerArchiveEntry {
            path: &entry.path,
            data: &entry.data,
        })
        .collect();

    let engine: InnerEngine = engine.into();
    let size = Decrypter::encrypted_buffer_size(&inner_entries, engine);
    let mut buffer = vec![0u8; size];

    let _ = Decrypter::new().encrypt(&inner_entries, engine, &mut buffer);

    buffer
}
