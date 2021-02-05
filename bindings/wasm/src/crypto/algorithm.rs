// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use wasm_bindgen::JsValue;

use crate::utils::err;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Algorithm {
  #[serde(rename = "ed25519")]
  Ed25519,
}

impl Algorithm {
  pub fn from_value(value: &JsValue) -> Result<Self, JsValue> {
    if value.is_falsy() {
      Ok(Self::Ed25519)
    } else {
      value.into_serde().map_err(err)
    }
  }
}
