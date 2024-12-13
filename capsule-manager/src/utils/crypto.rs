// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509};

use crate::common::constants;
use crate::error::errors::AuthResult;
use rand::prelude::StdRng;
use rand::SeedableRng;
use rsa::pkcs1::EncodeRsaPrivateKey;

pub fn create_cert(
    key_pair: &openssl::pkey::PKey<openssl::pkey::Private>,
    x509_names: std::collections::hash_map::Iter<&str, &str>,
    days: u32,
) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    for (&k, &v) in x509_names {
        x509_name.append_entry_by_text(k, v)?;
    }
    let x509_name = x509_name.build();
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;

    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before: Asn1Time = Asn1Time::from_unix(*constants::FIRST_SIGN_TIME)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after: Asn1Time =
        Asn1Time::from_unix(*constants::FIRST_SIGN_TIME + days as i64 * 24 * 60 * 60)?;
    cert_builder.set_not_after(&not_after)?;
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok(cert)
}

// return pkcs8 private key and X509 cert from seed
pub fn gen_rsa_key_pair_from_seed(seed: [u8; 32]) -> AuthResult<(String, String)> {
    let mut rng = StdRng::from_seed(seed);
    let rsa_pri_key = rsa::RsaPrivateKey::new(&mut rng, constants::RSA_BIT_LEN as usize)?;

    // rsa::pkcs1::error is a private module, can not impl From <rsa::pkcs1::error:Error> for Error
    // so we convert it to rsa::errors::Error first and then convert it to capsule manager's Error
    let pkcs1_res = rsa_pri_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF);
    let pkcs1_pri_key = match pkcs1_res {
        Ok(pkcs1_pri_key) => Ok(pkcs1_pri_key),
        Err(e) => Err(rsa::errors::Error::from(e)),
    }?;

    let openssl_pri_key = openssl::rsa::Rsa::private_key_from_pem(pkcs1_pri_key.as_bytes())?;
    let openssl_pkey = openssl::pkey::PKey::from_rsa(openssl_pri_key)?;

    // convert private key to pkcs8
    let pkcs8_pri_key = String::from_utf8(openssl_pkey.private_key_to_pem_pkcs8()?)?;

    let x509_cert = create_cert(
        &openssl_pkey,
        constants::X509NAME.iter(),
        constants::CERT_DAYS,
    )?;
    let x509_cert_pem = String::from_utf8(x509_cert.to_pem()?)?;

    Ok((pkcs8_pri_key, x509_cert_pem))
}
