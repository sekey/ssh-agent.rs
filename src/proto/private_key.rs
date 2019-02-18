use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error};
use serde::ser::{Serializer, SerializeTuple};

use std::mem::zeroed;
use std::ptr::write_volatile;

use super::error::ProtoError;
use super::key_type::{KeyType, KeyTypeEnum};

pub type MpInt = Vec<u8>;

macro_rules! ClearOnDrop {
    ($name:ident) => {
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe{ write_volatile(self, zeroed()) };
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DssPrivateKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt,
    pub x: MpInt
}
ClearOnDrop!(DssPrivateKey);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Ed25519PrivateKey {
    pub enc_a: Vec<u8>,
    pub k_enc_a: Vec<u8>
}
ClearOnDrop!(Ed25519PrivateKey);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateKey {
    pub n: MpInt,
    pub e: MpInt,
    pub d: MpInt,
    pub iqmp: MpInt,
    pub p: MpInt,
    pub q: MpInt
}
ClearOnDrop!(RsaPrivateKey);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EcDsaPrivateKey {
    pub identifier: String,
    pub q: MpInt,
    pub d: MpInt
}
ClearOnDrop!(EcDsaPrivateKey);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PrivateKey {
    Dss(DssPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Rsa(RsaPrivateKey),
    EcDsa(EcDsaPrivateKey)
}

impl KeyType for RsaPrivateKey {
    const KEY_TYPE: &'static str = "ssh-rsa";
}

impl KeyType for DssPrivateKey {
    const KEY_TYPE: &'static str = "ssh-dss";
}

impl KeyType for Ed25519PrivateKey {
    const KEY_TYPE: &'static str = "ssh-ed25519";
}

impl KeyType for EcDsaPrivateKey {
    const KEY_TYPE: &'static str = "ecdsa-sha2";
    
    fn key_type(&self) -> String {
        format!("{}-{}", Self::KEY_TYPE, self.identifier)
    }
}

impl_key_type_enum_ser_de!(
    PrivateKey,
    (PrivateKey::Dss, DssPrivateKey),
    (PrivateKey::Rsa, RsaPrivateKey),
    (PrivateKey::EcDsa, EcDsaPrivateKey),
    (PrivateKey::Ed25519, Ed25519PrivateKey)
);
