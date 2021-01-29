// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::{Object, Timestamp};
use iota::MessageId;

use crate::tangle::MessageIdExt;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Properties {
    pub(crate) created: Timestamp,
    pub(crate) updated: Timestamp,
    pub(crate) immutable: bool,
    #[serde(default = "MessageId::null", skip_serializing_if = "MessageIdExt::is_null")]
    pub(crate) previous_message_id: MessageId,
    #[serde(flatten)]
    pub(crate) properties: Object,
}

impl Properties {
    pub fn new() -> Self {
        Self {
            created: Timestamp::now(),
            updated: Timestamp::now(),
            immutable: false,
            previous_message_id: MessageId::null(),
            properties: Object::new(),
        }
    }
}

impl Default for Properties {
    fn default() -> Self {
        Self::new()
    }
}