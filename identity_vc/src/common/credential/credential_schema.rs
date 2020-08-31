use identity_core::common::Object;
use std::convert::TryFrom;

use crate::{
  common::{take_object_id, take_object_type, OneOrMany, URI},
  error::Error,
};

/// Information used to validate the structure of a `Credential`.
///
/// Ref: https://www.w3.org/TR/vc-data-model/#data-schemas
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CredentialSchema {
  pub id: URI,
  #[serde(rename = "type")]
  pub types: OneOrMany<String>,
  #[serde(flatten)]
  pub properties: Object,
}

impl TryFrom<Object> for CredentialSchema {
  type Error = Error;

  fn try_from(mut other: Object) -> Result<Self, Self::Error> {
    let mut this: Self = Default::default();

    this.id = match take_object_id(&mut other) {
      Some(id) => id.into(),
      None => return Err(Error::BadObjectConversion("CredentialSchema")),
    };

    this.types = match take_object_type(&mut other) {
      Some(types) => types,
      None => return Err(Error::BadObjectConversion("CredentialSchema")),
    };

    this.properties = other;

    Ok(this)
  }
}
