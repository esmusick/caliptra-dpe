// Licensed under the Apache-2.0 license

use crate::{AlgLen, Crypto, CryptoBuf, CryptoError, Digest, EcdsaPub, EcdsaSig, Hasher, HmacSig, hkdf::*};
use core::ops::Deref;
use elliptic_curve::{
    AffinePoint,
    point::PointCompression,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
     Curve, CurveArithmetic, FieldBytesSize, ScalarPrimitive, SecretKey,
};
use hmac::{Hmac, Mac};
use p256::NistP256;
use ecdsa::{Signature, signature::Signer};
use p384::NistP384;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{digest::DynDigest, Sha256, Sha384};
use std::boxed::Box;

const RUSTCRYPTO_EC_ERROR: CryptoError = CryptoError::CryptoLibError(1);
const RUSTCRYPTO_ECDSA_ERROR: CryptoError = CryptoError::CryptoLibError(2);

impl From<elliptic_curve::Error> for CryptoError {
    fn from(_value: elliptic_curve::Error) -> Self {
        RUSTCRYPTO_EC_ERROR
    }
}

impl From<ecdsa::Error> for CryptoError {
    fn from(_value: ecdsa::Error) -> Self {
        RUSTCRYPTO_ECDSA_ERROR
    }
}

impl TryFrom<Signature<NistP256>> for EcdsaSig {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP256>) -> Result<Self, Self::Error> {
        let r = CryptoBuf::new(&value.r().deref().to_bytes())?;
        let s = CryptoBuf::new(&value.s().deref().to_bytes())?;
        Ok(EcdsaSig { r, s })
    }
}
impl TryFrom<Signature<NistP384>> for EcdsaSig {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP384>) -> Result<Self, Self::Error> {
        let r = CryptoBuf::new(&value.r().deref().to_bytes())?;
        let s = CryptoBuf::new(&value.s().deref().to_bytes())?;
        Ok(EcdsaSig { r, s })
    }
}

pub struct RustCryptoHasher(Box<dyn DynDigest>);
impl Hasher for RustCryptoHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        Ok(self.0.update(bytes))
    }
    fn finish(self) -> Result<Digest, CryptoError> {
        Digest::new(&self.0.finalize())
    }
}

pub struct RustCryptoImpl(StdRng);
impl RustCryptoImpl {
    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        RustCryptoImpl(StdRng::from_entropy())
    }

    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        RustCryptoImpl(seeded_rng)
    }

    fn ec_key_from_secret_key<C: Curve>(
        secret_key: &CryptoBuf,
    ) -> Result<SecretKey<C>, elliptic_curve::Error> {
        // TODO: This is wrong. 
        // The only equivalent to mul_by_generator I found is implemented by ProjectivePoint, but I see no way to get from there to a SecretKey.
        // https://docs.rs/elliptic-curve/0.13.4/elliptic_curve/index.html#type-conversions
        let secret_scalar = ScalarPrimitive::from_slice(secret_key.bytes())?;
        Ok(SecretKey::new(secret_scalar))
    }

    fn get_keypair<C: Curve>(secret: &CryptoBuf) -> Result<EcdsaPub, CryptoError>
    where
        C: CurveArithmetic + PointCompression,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let secret_key = Self::ec_key_from_secret_key::<C>(&secret)?;
        // TODO: This is wrong.
        // openssl impl uses affine coordinates specificially, but AFAICT the y coordinate is not accessible on the AffinePoint type in RustCrypto?
        let point = EncodedPoint::<C>::from(secret_key.public_key());
        let x = CryptoBuf::new(point.x().ok_or(RUSTCRYPTO_EC_ERROR)?.as_slice())?;
        let y = CryptoBuf::new(point.y().ok_or(RUSTCRYPTO_EC_ERROR)?.as_slice())?;
        Ok(EcdsaPub { x, y })
    }
}

impl Crypto for RustCryptoImpl {
    type Cdi = Vec<u8>;
    type Hasher<'c>  = RustCryptoHasher where Self: 'c;
    type PrivKey = CryptoBuf;

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::Hasher<'_>, CryptoError> {
        let hasher = match algs {
            AlgLen::Bit256 => RustCryptoHasher(Box::new(Sha256::default())),
            AlgLen::Bit384 => RustCryptoHasher(Box::new(Sha384::default())),
        };
        Ok(hasher)
    }

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.0, dst);
        Ok(())
    }

    fn derive_cdi(
        &mut self,
        algs: AlgLen,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        hkdf_derive_cdi(algs, measurement, info)
    }

    fn derive_key_pair(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, EcdsaPub), CryptoError> {
        let secret = hkdf_get_priv_key(algs, cdi, label, info)?;
        match algs {
            AlgLen::Bit256 => {
                let public = RustCryptoImpl::get_keypair::<NistP256>(&secret)?;
                Ok((secret, public))
            }
            AlgLen::Bit384 => {
                let public = RustCryptoImpl::get_keypair::<NistP384>(&secret)?;
                Ok((secret, public))
            }
        }
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => {
                let ec_secret_key = SecretKey::from_sec1_pem(
                    std::str::from_utf8(include_bytes!(concat!(
                        env!("OUT_DIR"),
                        "/alias_priv_256.pem"
                    )))
                    .unwrap(),
                )
                .unwrap();
                let (sig, _) = p256::ecdsa::SigningKey::from(ec_secret_key).try_sign(digest.bytes())?;
                sig.try_into()
            }
            AlgLen::Bit384 => {
                let ec_secret_key = SecretKey::from_sec1_pem(
                    std::str::from_utf8(include_bytes!(concat!(
                        env!("OUT_DIR"),
                        "/alias_priv_384.pem"
                    )))
                    .unwrap(),
                )
                .unwrap();
                let (sig, _) = p384::ecdsa::SigningKey::from(ec_secret_key).try_sign(digest.bytes())?;
                sig.try_into()
            }
        }
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        algs: AlgLen,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &EcdsaPub,
    ) -> Result<EcdsaSig, CryptoError> {
        match algs {
            AlgLen::Bit256 => {
                let ec_secret_key = RustCryptoImpl::ec_key_from_secret_key(&priv_key)?;
                let (sig, _) = p256::ecdsa::SigningKey::from(ec_secret_key).try_sign(digest.bytes())?;
                sig.try_into()
            },
            AlgLen::Bit384 => {
                let ec_secret_key = RustCryptoImpl::ec_key_from_secret_key(&priv_key)?;
                let (sig, _) = p384::ecdsa::SigningKey::from(ec_secret_key).try_sign(digest.bytes())?;
                sig.try_into()
            }
        }
    }

    fn hmac_sign_with_derived(
        &mut self,
        algs: AlgLen,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
        digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        let (symmetric_key, _) = self.derive_key_pair(algs, cdi, label, info)?;
        match algs {
            AlgLen::Bit256 => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(symmetric_key.bytes()).unwrap();
                Mac::update(&mut hmac, digest.bytes());
                HmacSig::new(hmac.finalize().into_bytes().as_slice())
            },
            AlgLen::Bit384 => {
                let mut hmac = Hmac::<Sha384>::new_from_slice(symmetric_key.bytes()).unwrap();
                Mac::update(&mut hmac, digest.bytes());
                HmacSig::new(hmac.finalize().into_bytes().as_slice())
            }
        }
    }
}
