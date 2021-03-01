// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug)]
pub struct KeyLocation<'a> {
  identity: u32,
  fragment: &'a str,
}

impl<'a> KeyLocation<'a> {
  pub fn new(identity: u32, fragment: &'a str) -> Self {
    Self { identity, fragment }
  }

  pub fn identity(&self) -> u32 {
    self.identity
  }

  pub fn fragment(&self) -> &str {
    self.fragment
  }

  pub fn location(&self) -> String {
    format!("{}/{}", self.identity, self.fragment)
  }
}
