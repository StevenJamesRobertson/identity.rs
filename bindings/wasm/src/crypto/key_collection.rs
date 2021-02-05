// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity::core::encode_b58;
use identity::crypto::KeyCollection as KeyCollection_;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

use crate::crypto::Algorithm;
use crate::crypto::Digest;
use crate::crypto::KeyPair;
use crate::crypto::MerkleTree;
use crate::utils::err;

#[wasm_bindgen(inspectable)]
#[derive(Clone, Debug)]
pub struct KeyCollection(pub(crate) KeyCollection_);

#[wasm_bindgen]
impl KeyCollection {
  /// Creates a new `KeyCollection` with `ed25519` keys.
  #[wasm_bindgen(constructor)]
  pub fn new(algorithm: &JsValue, count: usize) -> Result<KeyCollection, JsValue> {
    match Algorithm::from_value(algorithm)? {
      Algorithm::Ed25519 => KeyCollection_::new_ed25519(count).map_err(err).map(Self),
    }
  }

  /// Returns the number of keys in the collection.
  #[wasm_bindgen(getter)]
  pub fn length(&self) -> usize {
    self.0.len()
  }

  /// Returns `true` if the collection contains no keys.
  #[wasm_bindgen(js_name = isEmpty)]
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// Returns the keypair at the specified `index`.
  #[wasm_bindgen]
  pub fn keypair(&self, index: usize) -> Option<KeyPair> {
    match self.0.public(index).zip(self.0.secret(index)) {
      Some((public, secret)) => todo!(),
      None => None,
    }
  }

  /// Returns the public key at the specified `index` as a base58-encoded string.
  #[wasm_bindgen]
  pub fn public(&self, index: usize) -> JsValue {
    match self.0.public(index) {
      Some(key) => encode_b58(key).into(),
      None => JsValue::NULL,
    }
  }

  /// Returns the secret key at the specified `index` as a base58-encoded string.
  #[wasm_bindgen]
  pub fn secret(&self, index: usize) -> JsValue {
    match self.0.secret(index) {
      Some(key) => encode_b58(key).into(),
      None => JsValue::NULL,
    }
  }

  /// Creates a new Merkle tree from the public keys in the collection.
  #[wasm_bindgen(js_name = toMerkleTree)]
  pub fn to_merkle_tree(&self, digest: &JsValue) -> Result<MerkleTree, JsValue> {
    match Digest::from_value(digest)? {
      Digest::Sha256 => match self.0.to_merkle_tree::<Sha256>() {
        Some(tree) => Ok(MerkleTree::new(Digest::Sha256, tree)),
        None => return Err("Invalid Merkle Tree".into()),
      },
    }
  }
}
