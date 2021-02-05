// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use identity::core::encode_b58;
use identity::crypto::merkle_tree::DigestExt;
use identity::crypto::merkle_tree::MTree;
use identity::crypto::merkle_tree::Node;
use identity::crypto::merkle_tree::Proof;
use sha2::digest::Output;
use wasm_bindgen::prelude::*;

use crate::crypto::Digest;

type DynHash = Vec<u8>;

pub trait DynamicNode: Debug {
  fn box_clone(&self) -> Box<dyn DynamicNode>;

  fn hash(&self) -> DynHash;

  fn side(&self) -> u8;
}

impl<D> DynamicNode for Node<D>
where
  D: DigestExt + 'static,
{
  fn box_clone(&self) -> Box<dyn DynamicNode> {
    Box::new(self.clone())
  }

  fn hash(&self) -> DynHash {
    self.get().as_ref().to_vec()
  }

  fn side(&self) -> u8 {
    match self {
      Node::L(_) => 0,
      Node::R(_) => 1,
    }
  }
}

// =============================================================================
// =============================================================================

pub trait DynamicProof: Debug {
  fn box_clone(&self) -> Box<dyn DynamicProof>;

  fn index(&self) -> usize;

  fn len(&self) -> usize;

  fn nodes(&self) -> Vec<&dyn DynamicNode>;

  fn node(&self, index: usize) -> Option<&dyn DynamicNode>;
}

impl<D> DynamicProof for Proof<D>
where
  D: DigestExt + 'static,
{
  fn box_clone(&self) -> Box<dyn DynamicProof> {
    Box::new(self.clone())
  }

  fn index(&self) -> usize {
    Proof::index(self)
  }

  fn len(&self) -> usize {
    Proof::nodes(self).len()
  }

  fn nodes(&self) -> Vec<&dyn DynamicNode> {
    Proof::nodes(self).iter().map(|node| node as &dyn DynamicNode).collect()
  }

  fn node(&self, index: usize) -> Option<&dyn DynamicNode> {
    Proof::nodes(self)
      .iter()
      .nth(index)
      .map(|node| node as &dyn DynamicNode)
  }
}

// =============================================================================
// =============================================================================

pub trait DynamicTree: Debug {
  fn box_clone(&self) -> Box<dyn DynamicTree>;

  fn root(&self) -> DynHash;

  fn proof(&self, index: usize) -> Option<Box<dyn DynamicProof>>;
}

impl<D> DynamicTree for MTree<D>
where
  D: DigestExt + 'static,
  Output<D>: Copy,
{
  fn box_clone(&self) -> Box<dyn DynamicTree> {
    Box::new(self.clone())
  }

  fn root(&self) -> DynHash {
    self.root().as_ref().to_vec()
  }

  fn proof(&self, index: usize) -> Option<Box<dyn DynamicProof>> {
    match MTree::proof(self, index) {
      Some(proof) => Some(Box::new(proof)),
      None => None,
    }
  }
}

// =============================================================================
// =============================================================================

#[wasm_bindgen(inspectable)]
#[derive(Debug)]
pub struct MerkleTree {
  pub(crate) digest: Digest,
  pub(crate) data: Box<dyn DynamicTree>,
}

#[wasm_bindgen]
impl MerkleTree {
  pub(crate) fn new(digest: Digest, data: impl DynamicTree + 'static) -> Self {
    Self {
      digest,
      data: Box::new(data),
    }
  }

  #[wasm_bindgen(getter)]
  pub fn root(&self) -> String {
    encode_b58(&self.data.root())
  }

  #[wasm_bindgen]
  pub fn proof(&self, index: usize) -> Result<MerkleProof, JsValue> {
    match self.data.proof(index) {
      Some(proof) => Ok(MerkleProof::new(self.digest, &*proof)),
      None => Err("Invalid Merkle Proof".into()),
    }
  }
}

// =============================================================================
// =============================================================================

#[wasm_bindgen(inspectable)]
#[derive(Debug)]
pub struct MerkleProof {
  pub(crate) digest: Digest,
  pub(crate) data: Box<dyn DynamicProof>,
}

#[wasm_bindgen]
impl MerkleProof {
  pub(crate) fn new(digest: Digest, data: &dyn DynamicProof) -> Self {
    Self {
      digest,
      data: data.box_clone(),
    }
  }

  #[wasm_bindgen(getter)]
  pub fn index(&self) -> usize {
    self.data.index()
  }

  #[wasm_bindgen(getter)]
  pub fn length(&self) -> usize {
    self.data.len()
  }

  #[wasm_bindgen]
  pub fn node(&self, index: usize) -> Result<MerkleNode, JsValue> {
    match self.data.node(index) {
      Some(node) => Ok(MerkleNode::new(self.digest, node)),
      None => Err("Invalid Merkle Proof Node".into()),
    }
  }
}

// =============================================================================
// =============================================================================

#[wasm_bindgen(inspectable)]
#[derive(Debug)]
pub struct MerkleNode {
  pub(crate) digest: Digest,
  pub(crate) data: Box<dyn DynamicNode>,
}

#[wasm_bindgen]
impl MerkleNode {
  pub(crate) fn new(digest: Digest, data: &dyn DynamicNode) -> Self {
    Self {
      digest,
      data: data.box_clone(),
    }
  }

  #[wasm_bindgen(getter)]
  pub fn hash(&self) -> String {
    encode_b58(&self.data.hash())
  }

  #[wasm_bindgen(getter)]
  pub fn side(&self) -> u8 {
    self.data.side()
  }
}
