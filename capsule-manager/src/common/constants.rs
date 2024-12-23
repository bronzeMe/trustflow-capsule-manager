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

use lazy_static::lazy_static;
use std::collections::HashMap;

// constant define
pub const RSA_BIT_LEN: u32 = 3072;
pub(crate) const HASH_SEPARATOR: &str = ".";
pub const CERT_DAYS: u32 = 365;
pub(crate) const TEE_PLATFORM_SGX: &str = "SGX_DCAP";
pub(crate) const TEE_PLATFORM_TDX: &str = "TDX";
pub(crate) const TEE_PLATFORM_HYPERENCLAVE: &str = "HyperEnclave";
const TEE_PLATFORM_CSV: &str = "CSV";

lazy_static! {
    pub static ref X509NAME: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("C", "CN");
        m.insert("ST", "HZ");
        m.insert("L", "HZ");
        m.insert("O", "AntGroup");
        m.insert("OU", "SecretFlow");
        m.insert("CN", "CapsuleManager");
        m
    };
}
