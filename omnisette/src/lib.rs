//! A library to generate "anisette" data. Docs are coming soon.
//!
//! If you want an async API, enable the `async` feature.
//!
//! If you want remote anisette, make sure the `remote-anisette` feature is enabled. (it's currently on by default)

use std::fmt::Formatter;
use std::path::PathBuf;

pub mod adi_proxy;
pub mod anisette_headers_provider;
pub mod store_services_core;
pub mod aoskit_emu;

#[cfg(target_os = "macos")]
pub mod aos_kit;

#[cfg(feature = "remote-anisette")]
pub mod remote_anisette;

#[allow(dead_code)]
pub struct AnisetteHeaders;

#[allow(dead_code)]
#[derive(Debug)]
enum AnisetteMetaError {
    #[allow(dead_code)]
    UnsupportedDevice,
    InvalidArgument(String),
}

impl std::fmt::Display for AnisetteMetaError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnisetteMetaError::{self:?}")
    }
}

impl std::error::Error for AnisetteMetaError {}

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

#[derive(Clone)]
pub struct AnisetteConfiguration {
    anisette_url: String,
    configuration_path: PathBuf,
}

impl Default for AnisetteConfiguration {
    fn default() -> Self {
        AnisetteConfiguration::new()
    }
}

impl AnisetteConfiguration {
    pub fn new() -> AnisetteConfiguration {
        AnisetteConfiguration {
            anisette_url: DEFAULT_ANISETTE_URL.to_string(),
            configuration_path: PathBuf::new(),
        }
    }

    pub fn anisette_url(&self) -> &String {
        &self.anisette_url
    }

    pub fn configuration_path(&self) -> &PathBuf {
        &self.configuration_path
    }

    pub fn set_anisette_url(mut self, anisette_url: String) -> AnisetteConfiguration {
        self.anisette_url = anisette_url;
        self
    }

    pub fn set_configuration_path(mut self, configuration_path: PathBuf) -> AnisetteConfiguration {
        self.configuration_path = configuration_path;
        self
    }
}
