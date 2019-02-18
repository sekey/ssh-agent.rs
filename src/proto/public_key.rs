use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error};
use serde::ser::{Serializer, SerializeTuple};

use std::mem::{replace, zeroed};

use super::error::ProtoError;
use super::private_key::*;
use super::key_type::{KeyType, KeyTypeEnum};

pub type MpInt = Vec<u8>;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RsaPublicKey {
    pub e: MpInt,
    pub n: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DssPublicKey {
    pub p: MpInt,
    pub q: MpInt,
    pub g: MpInt,
    pub y: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EcDsaPublicKey {
    pub identifier: String,
    pub q: MpInt
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    pub enc_a: Vec<u8>
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PublicKey {
    Dss(DssPublicKey),
    Ed25519(Ed25519PublicKey),
    Rsa(RsaPublicKey),
    EcDsa(EcDsaPublicKey)
}

impl KeyType for RsaPublicKey {
    const KEY_TYPE: &'static str = RsaPrivateKey::KEY_TYPE;
}

impl KeyType for DssPublicKey {
    const KEY_TYPE: &'static str = DssPrivateKey::KEY_TYPE;
}

impl KeyType for Ed25519PublicKey {
    const KEY_TYPE: &'static str = Ed25519PrivateKey::KEY_TYPE;
}

impl KeyType for EcDsaPublicKey {
    const KEY_TYPE: &'static str = EcDsaPrivateKey::KEY_TYPE;
    
    fn key_type(&self) -> String {
        format!("{}-{}", Self::KEY_TYPE, self.identifier)
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(key: PrivateKey) -> Self {
        match key {
            PrivateKey::Dss(key) => PublicKey::Dss(DssPublicKey::from(key)),
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(Ed25519PublicKey::from(key)),
            PrivateKey::Rsa(key) => PublicKey::Rsa(RsaPublicKey::from(key)),
            PrivateKey::EcDsa(key) => PublicKey::EcDsa(EcDsaPublicKey::from(key)),
        }
    }
}

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(mut key: RsaPrivateKey) -> Self {
        Self {
            e: replace(&mut key.e, unsafe { zeroed() }),
            n: replace(&mut key.n, unsafe { zeroed() })
        }
    }
}

impl From<DssPrivateKey> for DssPublicKey {
    fn from(mut key: DssPrivateKey) -> Self {
        Self {
            p: replace(&mut key.p, unsafe { zeroed() }),
            q: replace(&mut key.q, unsafe { zeroed() }),
            g: replace(&mut key.g, unsafe { zeroed() }),
            y: replace(&mut key.y, unsafe { zeroed() })
        }
    }
}

impl From<EcDsaPrivateKey> for EcDsaPublicKey {
    fn from(mut key: EcDsaPrivateKey) -> Self {
        Self {
            identifier: replace(&mut key.identifier, unsafe { zeroed() }),
            q: replace(&mut key.q, unsafe { zeroed() })
        }
    }
}

impl From<Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(mut key: Ed25519PrivateKey) -> Self {
        Self {
            enc_a: replace(&mut key.enc_a, unsafe { zeroed() })
        }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(key: &PrivateKey) -> Self {
        Self::from(key.clone())
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(key: &RsaPrivateKey) -> Self {
        Self::from(key.clone())
    }
}

impl From<&DssPrivateKey> for DssPublicKey {
    fn from(key: &DssPrivateKey) -> Self {
        Self::from(key.clone())
    }
}

impl From<&EcDsaPrivateKey> for EcDsaPublicKey {
    fn from(key: &EcDsaPrivateKey) -> Self {
        Self::from(key.clone())
    }
}

impl From<&Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(key: &Ed25519PrivateKey) -> Self {
        Self::from(key.clone())
    }
}

impl_key_type_enum_ser_de!(
    PublicKey,
    (PublicKey::Dss, DssPublicKey),
    (PublicKey::Rsa, RsaPublicKey),
    (PublicKey::EcDsa, EcDsaPublicKey),
    (PublicKey::Ed25519, Ed25519PublicKey)
);
