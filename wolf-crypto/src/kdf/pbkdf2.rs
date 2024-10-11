//! The Password Based Key Derivation Function 2 (PBKDF2)

use wolf_crypto_sys::{wc_PBKDF2};

use crate::aead::Aad as Additional;
use crate::{can_cast_u32, const_can_cast_u32, Unspecified};
use crate::kdf::Salt;

use crate::mac::hmac::algo::{GenericKey, Hash};

