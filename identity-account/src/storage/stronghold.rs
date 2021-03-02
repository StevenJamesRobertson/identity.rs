// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use identity_core::crypto::KeyType;
use identity_core::crypto::PublicKey;
use iota_stronghold::hd::Chain;
use iota_stronghold::Location;
use iota_stronghold::SLIP10DeriveInput;
use std::path::Path;

use crate::error::Result;
use crate::storage::KeyLocation;
use crate::storage::Signature;
use crate::storage::StorageAdapter;
use crate::storage::VaultAdapter;
use crate::stronghold::default_hint;
use crate::stronghold::Records;
use crate::stronghold::Snapshot;
use crate::stronghold::Vault;
use crate::utils::EncryptionKey;

#[derive(Debug)]
pub struct StrongholdAdapter {
  snapshot: Snapshot,
}

impl StrongholdAdapter {
  pub async fn new<P>(path: &P, password: Option<EncryptionKey>) -> Result<Self>
  where
    P: AsRef<Path> + ?Sized,
  {
    let snapshot: Snapshot = Snapshot::new(path);

    if let Some(password) = password {
      snapshot.load(password).await?;
    }

    Ok(Self { snapshot })
  }

  fn records(&self) -> Records<'_> {
    self.snapshot.records("identity", &[])
  }

  fn keystore(&self, location: KeyLocation<'_>) -> Vault<'_> {
    self
      .snapshot
      .vault(format!("keystore:{}", location.identity()).as_bytes(), &[])
  }
}

#[async_trait::async_trait]
impl StorageAdapter for StrongholdAdapter {
  async fn all(&mut self) -> Result<Vec<Vec<u8>>> {
    self.records().all().await
  }

  async fn get(&mut self, resource_id: &[u8]) -> Result<Vec<u8>> {
    self.records().get(resource_id).await
  }

  async fn set(&mut self, resource_id: &[u8], resource: &[u8]) -> Result<()> {
    let records: Records<'_> = self.records();

    records.set(resource_id, resource).await?;
    records.flush().await?;

    Ok(())
  }

  async fn del(&mut self, resource_id: &[u8]) -> Result<()> {
    let records: Records<'_> = self.records();

    records.del(resource_id).await?;
    records.flush().await?;

    Ok(())
  }

  fn storage_path(&self) -> &Path {
    self.snapshot.path()
  }
}

#[async_trait::async_trait]
impl VaultAdapter for StrongholdAdapter {
  async fn generate_public_key(&mut self, type_: KeyType, location: KeyLocation<'_>) -> Result<PublicKey> {
    let vault: Vault<'_> = self.keystore(location);

    let public: PublicKey = match type_ {
      KeyType::Ed25519 => generate_ed25519(&vault, location).await?,
    };

    // // Write to disk
    // vault.flush().await?;

    Ok(public)
  }

  async fn retrieve_public_key(&mut self, type_: KeyType, location: KeyLocation<'_>) -> Result<PublicKey> {
    let vault: Vault<'_> = self.keystore(location);

    match type_ {
      KeyType::Ed25519 => retrieve_ed25519(&vault, location).await,
    }
  }

  async fn generate_signature(
    &mut self,
    payload: Vec<u8>,
    type_: KeyType,
    location: KeyLocation<'_>,
  ) -> Result<Signature> {
    let vault: Vault<'_> = self.keystore(location);

    match type_ {
      KeyType::Ed25519 => sign_ed25519(&vault, payload, location).await,
    }
  }
}

async fn generate_ed25519(vault: &Vault<'_>, location: KeyLocation<'_>) -> Result<PublicKey> {
  let location_seed: Location = Location::generic("vault:seed", location.fragment());
  let location_skey: Location = Location::generic("vault:skey", location.fragment());

  // Generate a SLIP10 seed as the private key
  vault
    .slip10_generate(location_seed.clone(), default_hint(), None)
    .await?;

  let chain: Chain = Chain::from_u32_hardened(vec![0, 0, 0]);
  let seed: SLIP10DeriveInput = SLIP10DeriveInput::Seed(location_seed);

  // Use the SLIP10 seed to derive a child key
  vault
    .slip10_derive(chain, seed, location_skey.clone(), default_hint())
    .await?;

  // Retrieve the public key of the derived child key
  let public: [u8; 32] = vault.ed25519_public_key(location_skey).await?;
  let public: PublicKey = public.to_vec().into();

  Ok(public)
}

async fn retrieve_ed25519(vault: &Vault<'_>, location: KeyLocation<'_>) -> Result<PublicKey> {
  let location: Location = Location::generic("vault:skey", location.fragment());

  let public: [u8; 32] = vault.ed25519_public_key(location).await?;
  let public: PublicKey = public.to_vec().into();

  Ok(public)
}

async fn sign_ed25519(vault: &Vault<'_>, payload: Vec<u8>, location: KeyLocation<'_>) -> Result<Signature> {
  let public_key: PublicKey = retrieve_ed25519(vault, location).await?;

  let location: Location = Location::generic("vault:skey", location.fragment());
  let signature: [u8; 64] = vault.ed25519_sign(payload, location).await?;

  Ok(Signature::new(public_key, signature.into()))
}

#[cfg(test)]
mod tests {
  use core::convert::TryInto;
  use core::iter;
  use crypto::ed25519;
  use identity_core::crypto::KeyType;
  use identity_core::crypto::PublicKey;
  use rand::distributions::Alphanumeric;
  use rand::rngs::OsRng;
  use rand::Rng;
  use std::collections::HashMap;
  use std::fs;
  use std::path::Path;
  use std::path::PathBuf;

  use crate::storage::KeyLocation;
  use crate::storage::StrongholdAdapter;
  use crate::storage::VaultAdapter;
  use crate::storage::Signature;
  use crate::stronghold::Records;
  use crate::stronghold::Snapshot;
  use crate::utils::derive_encryption_key;
  use crate::utils::EncryptionKey;

  const MAX_I: u32 = 5;
  const MAX_K: u32 = 1;

  #[tokio::test]
  async fn test_stronghold_adapter() {
    fs::create_dir_all("./test-storage").unwrap();

    let filename: &Path = "./test-storage/snapshot.stronghold".as_ref();
    let password: EncryptionKey = derive_encryption_key("my-password");

    if filename.exists() {
      fs::remove_file(filename).unwrap();
    }

    let mut adapter: _ = StrongholdAdapter::new(filename, Some(password)).await.unwrap();

    let mut out_keys: HashMap<u32, HashMap<u32, PublicKey>> = HashMap::new();
    let mut out_sigs: HashMap<u32, HashMap<u32, Signature>> = HashMap::new();

    for identity in 0..MAX_I {
      for key in 0..MAX_K {
        let fragment: String = format!("key-{}", key);
        let location: KeyLocation = KeyLocation::new(identity, &fragment);

        let public_a: PublicKey = adapter.generate_public_key(KeyType::Ed25519, location).await.unwrap();
        let public_b: PublicKey = adapter.retrieve_public_key(KeyType::Ed25519, location).await.unwrap();

        assert_eq!(public_a.as_ref(), public_b.as_ref());

        out_keys.entry(identity).or_default().insert(key, public_a);
      }
    }

    for identity in 0..MAX_I {
      for key in 0..MAX_K {
        let fragment: String = format!("key-{}", key);
        let location: KeyLocation = KeyLocation::new(identity, &fragment);
        let signature: Signature = adapter.generate_signature(b"IOTA".to_vec(), KeyType::Ed25519, location).await.unwrap();

        out_sigs.entry(identity).or_default().insert(key, signature);
      }
    }

    for identity in 0..MAX_I {
      for key in 0..MAX_K {
        let fragment: String = format!("key-{}", key);
        let location: KeyLocation = KeyLocation::new(identity, &fragment);

        let snapshot: PublicKey = adapter.retrieve_public_key(KeyType::Ed25519, location).await.unwrap();
        let hashmap: &PublicKey = &out_keys[&identity][&key];

        assert_eq!(snapshot.as_ref(), hashmap.as_ref());
      }
    }

    for identity in 0..MAX_I {
      for key in 0..MAX_K {
        let public_key: &PublicKey = &out_keys[&identity][&key];
        let signature: &Signature = &out_sigs[&identity][&key];

        assert_eq!(public_key.as_ref(), signature.public_key().as_ref());

        let public: ed25519::PublicKey = {
          let bytes: [u8; 32] = public_key.as_ref().try_into().unwrap();
          ed25519::PublicKey::from_compressed_bytes(bytes).unwrap()
        };

        let signature: ed25519::Signature = {
          let bytes: [u8; 64] = signature.signature().try_into().unwrap();
          ed25519::Signature::from_bytes(bytes)
        };

        assert_eq!(ed25519::verify(&public, &signature, b"IOTA"), true);
      }
    }

    fs::remove_file(filename).unwrap();
  }

  fn rand_string(chars: usize) -> String {
    iter::repeat(())
      .map(|_| OsRng.sample(Alphanumeric))
      .map(char::from)
      .take(chars)
      .collect()
  }

  fn snapshot_path(root: &str, chars: usize) -> PathBuf {
    AsRef::<Path>::as_ref(root).join(format!("{}.stronghold", rand_string(chars)))
  }

  const RECORDS: u32 = 2;

  #[tokio::test]
  async fn test_record_get_set() {
    fs::create_dir_all("./test-storage").unwrap();

    let location: PathBuf = snapshot_path("./test-storage", 10);
    let snapshot: Snapshot = Snapshot::new(&location);

    snapshot.load([0; 32]).await.unwrap();

    let records: Records<'_> = snapshot.records("", &[]);

    assert_eq!(records.all().await.unwrap().len(), 0);

    for index in 0..RECORDS {
      records
        .set(&index.to_be_bytes(), &index.pow(2).to_be_bytes())
        .await
        .unwrap();
    }

    for index in 0..RECORDS {
      let data: Vec<u8> = records.get(&index.to_be_bytes()).await.unwrap();
      assert_eq!(data, &index.pow(2).to_be_bytes());
    }

    for index in RECORDS..(RECORDS * 2) {
      let data: Vec<u8> = records.get(&index.to_be_bytes()).await.unwrap();
      assert_eq!(data, Vec::<u8>::new());
    }

    snapshot.unload(true).await.unwrap();
    snapshot.load([0; 32]).await.unwrap();

    for index in 0..RECORDS {
      let data: Vec<u8> = records.get(&index.to_be_bytes()).await.unwrap();
      assert_eq!(data, &index.pow(2).to_be_bytes());
    }

    for index in 0..RECORDS {
      records.del(&index.to_be_bytes()).await.unwrap();
    }

    for index in 0..RECORDS {
      let data: Vec<u8> = records.get(&index.to_be_bytes()).await.unwrap();
      assert_eq!(data, Vec::<u8>::new());
    }

    fs::remove_file(&location).unwrap();
  }
}
