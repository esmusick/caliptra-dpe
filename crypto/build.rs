// Licensed under the Apache-2.0 license

#[cfg(feature="rustcrypto")]
use std::ops::Deref;

fn main() {
    #[cfg(feature = "openssl")]
    {
        use {
            fs::File,
            openssl::{ec, nid, pkey},
            std::env,
            std::fs,
            std::io::Write,
            std::path::Path,
        };

        const ALIAS_PRIV_256: &str = "../platform/src/test_data/key_256.pem";
        const ALIAS_PRIV_384: &str = "../platform/src/test_data/key_384.pem";

        const CURVE_ID_256: nid::Nid = nid::Nid::X9_62_PRIME256V1;
        const CURVE_ID_384: nid::Nid = nid::Nid::SECP384R1;

        println!("cargo:rerun-if-changed={ALIAS_PRIV_256}");
        println!("cargo:rerun-if-changed={ALIAS_PRIV_384}");

        let out_dir = env::var_os("OUT_DIR").unwrap();

        // generate 256 bit private key in PEM format
        let pem_256 = if Path::new(ALIAS_PRIV_256).exists() {
            let input_pem = fs::read(ALIAS_PRIV_256).unwrap();
            let ec_priv: ec::EcKey<pkey::Private> =
                ec::EcKey::private_key_from_pem(&input_pem).unwrap();
            ec_priv.private_key_to_pem().unwrap()
        } else {
            let group = ec::EcGroup::from_curve_name(CURVE_ID_256).unwrap();
            let ec_key = ec::EcKey::generate(&group).unwrap();
            ec_key.private_key_to_pem().unwrap()
        };

        // generate 384 bit private key in PEM format
        let pem_384 = if Path::new(ALIAS_PRIV_384).exists() {
            let input_pem = fs::read(ALIAS_PRIV_384).unwrap();
            let ec_priv: ec::EcKey<pkey::Private> =
                ec::EcKey::private_key_from_pem(&input_pem).unwrap();
            ec_priv.private_key_to_pem().unwrap()
        } else {
            let group = ec::EcGroup::from_curve_name(CURVE_ID_384).unwrap();
            let ec_key = ec::EcKey::generate(&group).unwrap();
            ec_key.private_key_to_pem().unwrap()
        };

        // write 256 bit private key to file
        let path_256 = Path::new(&out_dir).join("alias_priv_256.pem");
        let mut sample_alias_key_file_256 = File::create(path_256).unwrap();
        sample_alias_key_file_256.write_all(&pem_256).unwrap();

        // write 384 bit private key to file
        let path_384 = Path::new(&out_dir).join("alias_priv_384.pem");
        let mut sample_alias_key_file_384 = File::create(path_384).unwrap();
        sample_alias_key_file_384.write_all(&pem_384).unwrap();
    }
    #[cfg(feature = "rustcrypto")]
    {
        use {
            elliptic_curve::{SecretKey},
            fs::File,
            p256::NistP256,
            p384::NistP384,
            base64ct::LineEnding,
            rand::{rngs::StdRng, SeedableRng},
            std::env,
            std::fs,
            std::str,
            std::io::Write,
            std::path::Path,
        };

        const ALIAS_PRIV_256: &str = "../platform/src/test_data/key_256.pem";
        const ALIAS_PRIV_384: &str = "../platform/src/test_data/key_384.pem";

        println!("cargo:rerun-if-changed={ALIAS_PRIV_256}");
        println!("cargo:rerun-if-changed={ALIAS_PRIV_384}");

        let out_dir = env::var_os("OUT_DIR").unwrap();

        // generate 256 bit private key in PEM format
        let pem_256 = if Path::new(ALIAS_PRIV_256).exists() {
            let input_pem = fs::read(ALIAS_PRIV_256).unwrap();
            let ec_secret = SecretKey::<NistP256>::from_sec1_pem(str::from_utf8(&input_pem).unwrap()).unwrap();
            ec_secret.to_sec1_pem(LineEnding::default()).unwrap()
        } else {
            let ec_secret = SecretKey::<NistP256>::random(&mut StdRng::from_entropy());
            ec_secret.to_sec1_pem(LineEnding::default()).unwrap()
        };

        // generate 384 bit private key in PEM format
        let pem_384 = if Path::new(ALIAS_PRIV_384).exists() {
            let input_pem = fs::read(ALIAS_PRIV_384).unwrap();
            let ec_secret = SecretKey::<NistP384>::from_sec1_pem(str::from_utf8(&input_pem).unwrap()).unwrap();
            ec_secret.to_sec1_pem(LineEnding::default()).unwrap()
        } else {
            let ec_secret = SecretKey::<NistP384>::random(&mut StdRng::from_entropy());
            ec_secret.to_sec1_pem(LineEnding::default()).unwrap()
        };

        // write 256 bit private key to file
        let path_256 = Path::new(&out_dir).join("alias_priv_256.pem");
        let mut sample_alias_key_file_256 = File::create(path_256).unwrap();
        sample_alias_key_file_256
            .write_all(pem_256.deref().as_bytes())
            .unwrap();

        // write 384 bit private key to file
        let path_384 = Path::new(&out_dir).join("alias_priv_384.pem");
        let mut sample_alias_key_file_384 = File::create(path_384).unwrap();
        sample_alias_key_file_384
            .write_all(pem_384.deref().as_bytes())
            .unwrap();
    }
}
