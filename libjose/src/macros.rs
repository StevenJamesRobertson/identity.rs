#[macro_export]
macro_rules! gen_bytes {
  ($length:expr) => {{
    let mut __array: [u8; $length] = [0; $length];
    ::crypto::rand::fill(&mut __array).map(|_| __array)
  }};
}

#[macro_export]
macro_rules! rsa_padding {
  (@PKCS1_SHA256) => {
    ::rsa::PaddingScheme::new_pkcs1v15_sign(Some(::rsa::Hash::SHA2_256))
  };
  (@PKCS1_SHA384) => {
    ::rsa::PaddingScheme::new_pkcs1v15_sign(Some(::rsa::Hash::SHA2_384))
  };
  (@PKCS1_SHA512) => {
    ::rsa::PaddingScheme::new_pkcs1v15_sign(Some(::rsa::Hash::SHA2_512))
  };
  (@PSS_SHA256) => {
    ::rsa::PaddingScheme::new_pss::<::sha2::Sha256, _>(::rand::rngs::OsRng)
  };
  (@PSS_SHA384) => {
    ::rsa::PaddingScheme::new_pss::<::sha2::Sha384, _>(::rand::rngs::OsRng)
  };
  (@PSS_SHA512) => {
    ::rsa::PaddingScheme::new_pss::<::sha2::Sha512, _>(::rand::rngs::OsRng)
  };
  (@RSA1_5) => {
    ::rsa::PaddingScheme::new_pkcs1v15_encrypt()
  };
  (@RSA_OAEP) => {
    ::rsa::PaddingScheme::new_oaep::<::sha1::Sha1>()
  };
  (@RSA_OAEP_256) => {
    ::rsa::PaddingScheme::new_oaep::<::sha2::Sha256>()
  };
  (@RSA_OAEP_384) => {
    ::rsa::PaddingScheme::new_oaep::<::sha2::Sha384>()
  };
  (@RSA_OAEP_512) => {
    ::rsa::PaddingScheme::new_oaep::<::sha2::Sha512>()
  };
}