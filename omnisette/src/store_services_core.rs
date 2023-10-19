#[cfg(target_os = "macos")]
mod posix_macos;
#[cfg(target_family = "windows")]
mod posix_windows;

use crate::{
    adi_proxy::{
        ADIError, ADIProxy, ConfigurableADIProxy, RequestOTPData, StartProvisioningData,
        SynchronizeData,
    },
    aoskit_emu::{MachHook, set_android_id_stub, set_android_prov_path_stub}
};

use android_loader::android_library::AndroidLibrary;
use android_loader::sysv64_type;
use android_loader::{hook_manager, sysv64};
use anyhow::Result;
use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::path::{Path, PathBuf};
use std::mem::transmute;

pub struct StoreServicesCoreADIProxy {
	// we need to keep the library around 'cause every implementation so far memmaps the data,
	// so we need to make sure it's not dropped
	#[allow(dead_code)]
	library: Box<dyn std::any::Any>,

    local_user_uuid: String,
    device_identifier: String,

    adi_set_android_id: sysv64_type!(fn(id: *const u8, length: u32) -> i32),
    adi_set_provisioning_path: sysv64_type!(fn(path: *const u8) -> i32),

    adi_provisioning_erase: sysv64_type!(fn(ds_id: i64) -> i32),
    adi_synchronize: sysv64_type!(
        fn(
            ds_id: i64,
            sim: *const u8,
            sim_length: u32,
            out_mid: *mut *const u8,
            out_mid_length: *mut u32,
            out_srm: *mut *const u8,
            out_srm_length: *mut u32,
        ) -> i32
    ),
    adi_provisioning_destroy: sysv64_type!(fn(session: u32) -> i32),
    adi_provisioning_end: sysv64_type!(
        fn(session: u32, ptm: *const u8, ptm_length: u32, tk: *const u8, tk_length: u32) -> i32
    ),
    adi_provisioning_start: sysv64_type!(
        fn(
            ds_id: i64,
            spim: *const u8,
            spim_length: u32,
            out_cpim: *mut *const u8,
            out_cpim_length: *mut u32,
            out_session: *mut u32,
        ) -> i32
    ),
    adi_get_login_code: sysv64_type!(fn(ds_id: i64) -> i32),
    adi_dispose: sysv64_type!(fn(ptr: *const u8) -> i32),
    adi_otp_request: sysv64_type!(
        fn(
            ds_id: i64,
            out_mid: *mut *const u8,
            out_mid_size: *mut u32,
            out_otp: *mut *const u8,
            out_otp_size: *mut u32,
        ) -> i32
    ),
}

impl StoreServicesCoreADIProxy {
    pub fn new(library_path: &PathBuf) -> Result<StoreServicesCoreADIProxy> {
        Self::with_custom_provisioning_path(library_path, library_path)
    }

    pub fn with_custom_provisioning_path(library_path: &PathBuf, provisioning_path: &Path) -> Result<StoreServicesCoreADIProxy> {
        LoaderHelpers::setup_hooks();

        if !library_path.exists() {
            std::fs::create_dir(library_path)?;
            return Err(ADIStoreSericesCoreErr::MissingLibraries.into());
        }

        let library_path = library_path.canonicalize()?;

        #[cfg(target_arch = "x86_64")]
        const ARCH: &str = "x86_64";
        #[cfg(target_arch = "x86")]
        const ARCH: &str = "x86";
        #[cfg(target_arch = "arm")]
        const ARCH: &str = "armeabi-v7a";
        #[cfg(target_arch = "aarch64")]
        const ARCH: &str = "arm64-v8a";

        let native_library_path = library_path.join("lib").join(ARCH);

        let path = native_library_path.join("libstoreservicescore.so");
        let path = path.to_str().ok_or(ADIStoreSericesCoreErr::Misc)?;
        let store_services_core = AndroidLibrary::load(path)?;

        let adi_load_library_with_path: sysv64_type!(fn(path: *const u8) -> i32) =
            unsafe {
                transmute(
                    store_services_core
                        .get_symbol("kq56gsgHG6")
                        .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?,
                )
            };

        let path = CString::new(
            native_library_path
                .to_str()
                .ok_or(ADIStoreSericesCoreErr::Misc)?,
        )
        .unwrap();
        assert_eq!((adi_load_library_with_path)(path.as_ptr() as *const u8), 0);

        let adi_set_android_id = store_services_core
            .get_symbol("Sph98paBcz")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_set_provisioning_path = store_services_core
            .get_symbol("nf92ngaK92")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;

        let adi_provisioning_erase = store_services_core
            .get_symbol("p435tmhbla")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_synchronize = store_services_core
            .get_symbol("tn46gtiuhw")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_provisioning_destroy = store_services_core
            .get_symbol("fy34trz2st")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_provisioning_end = store_services_core
            .get_symbol("uv5t6nhkui")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_provisioning_start = store_services_core
            .get_symbol("rsegvyrt87")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_get_login_code = store_services_core
            .get_symbol("aslgmuibau")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_dispose = store_services_core
            .get_symbol("jk24uiwqrg")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;
        let adi_otp_request = store_services_core
            .get_symbol("qi864985u0")
            .ok_or(ADIStoreSericesCoreErr::InvalidLibraryFormat)?;

        let mut proxy = unsafe { StoreServicesCoreADIProxy {
			library: Box::new(store_services_core),
            local_user_uuid: String::new(),
            device_identifier: String::new(),

            adi_set_android_id: transmute(adi_set_android_id),
            adi_set_provisioning_path: transmute(adi_set_provisioning_path),

            adi_provisioning_erase: transmute(adi_provisioning_erase),
            adi_synchronize: transmute(adi_synchronize),
            adi_provisioning_destroy: transmute(adi_provisioning_destroy),
            adi_provisioning_end: transmute(adi_provisioning_end),
            adi_provisioning_start: transmute(adi_provisioning_start),
            adi_get_login_code: transmute(adi_get_login_code),
            adi_dispose: transmute(adi_dispose),
            adi_otp_request: transmute(adi_otp_request),
        }};

        proxy.set_provisioning_path(
            provisioning_path.to_str().ok_or(ADIStoreSericesCoreErr::Misc)?,
        )?;

        Ok(proxy)
    }

    pub fn from_macos_aoskit<P: AsRef<Path>>(path: P) -> Result<StoreServicesCoreADIProxy> {
        let mut hook = MachHook::new(&path, None)?;

        hook.hook_fn("_arc4random", arc4random as *const ())?;
        hook.hook_fn("_close", libc::close as *const ())?;
        hook.hook_fn("_free", libc::free as *const ())?;
        hook.hook_fn("_gettimeofday", libc::gettimeofday as *const ())?;
        hook.hook_fn("_malloc", libc::malloc as *const ())?;
        hook.hook_fn("_open", libc::open as *const ())?;
        hook.hook_fn("_dlsym", MachHook::dlsym as *const ())?;
        hook.hook_fn("_dlopen", MachHook::dlopen as *const ())?;

        // The symbols that may not be present, so we're ok if trying to replace them returns an error
        _ = hook.hook_fn("_read", libc::read as *const ());
        _ = hook.hook_fn("_strncpy", libc::strncpy as *const ());
        _ = hook.hook_fn("_umask", libc::umask as *const ());
        _ = hook.hook_fn("_write", libc::write as *const ());
        _ = hook.hook_fn("_mkdir", libc::mkdir as *const ());
        _ = hook.hook_fn("_lstat", libc::lstat as *const ());
        _ = hook.hook_fn("_fstat", libc::fstat as *const ());
        _ = hook.hook_fn("_ftruncate", libc::ftruncate as *const ());
        _ = hook.hook_fn("_chmod", libc::chmod as *const ());
        _ = hook.hook_fn("___system_property_get", __system_property_get as *const ());
        _ = hook.hook_fn("___errno", __errno_location as *const ());
        _ = hook.hook_fn("_dlclose", MachHook::dlclose as *const ());

        let adi_provisioning_erase = hook.get_symbol_ptr("_p435tmhbla").unwrap();
        let adi_synchronize = hook.get_symbol_ptr("_tn46gtiuhw").unwrap();
        let adi_provisioning_destroy = hook.get_symbol_ptr("_fy34trz2st").unwrap();
        let adi_provisioning_end = hook.get_symbol_ptr("_uv5t6nhkui").unwrap();
        let adi_provisioning_start = hook.get_symbol_ptr("_rsegvyrt87").unwrap();
        let adi_get_login_code = hook.get_symbol_ptr("_aslgmuibau").unwrap();
        let adi_dispose = hook.get_symbol_ptr("_jk24uiwqrg").unwrap();
        let adi_otp_request = hook.get_symbol_ptr("_qi864985u0").unwrap();

		println!("erase: {adi_provisioning_erase:?}");

        let provider = unsafe {
            StoreServicesCoreADIProxy {
				library: Box::new(hook),
                local_user_uuid: String::new(),
                device_identifier: String::new(),
                adi_set_android_id: set_android_id_stub,
                adi_set_provisioning_path: set_android_prov_path_stub,
                adi_provisioning_erase: transmute(adi_provisioning_erase),
                adi_synchronize: transmute(adi_synchronize),
                adi_provisioning_destroy: transmute(adi_provisioning_destroy),
                adi_provisioning_end: transmute(adi_provisioning_end),
                adi_provisioning_start: transmute(adi_provisioning_start),
                adi_get_login_code: transmute(adi_get_login_code),
                adi_dispose: transmute(adi_dispose),
                adi_otp_request: transmute(adi_otp_request),
            }
        };

        Ok(provider)
    }
}

impl ADIProxy for StoreServicesCoreADIProxy {
    fn erase_provisioning(&mut self, ds_id: i64) -> Result<(), ADIError> {
        match (self.adi_provisioning_erase)(ds_id) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn synchronize(&mut self, ds_id: i64, sim: &[u8]) -> Result<SynchronizeData, ADIError> {
        let sim_size = sim.len() as u32;
        let sim_ptr = sim.as_ptr();

        let mut mid_size: u32 = 0;
        let mut mid_ptr: *const u8 = std::ptr::null();
        let mut srm_size: u32 = 0;
        let mut srm_ptr: *const u8 = std::ptr::null();

        match (self.adi_synchronize)(
            ds_id,
            sim_ptr,
            sim_size,
            &mut mid_ptr,
            &mut mid_size,
            &mut srm_ptr,
            &mut srm_size,
        ) {
            0 => {
                let mut mid = vec![0; mid_size as usize];
                let mut srm = vec![0; srm_size as usize];

                // SAFETY: This is safe as long as the library returned initialized data at these
                // locations - because the function returned 0, we are trusting that it did.
                unsafe {
                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    srm.copy_from_slice(std::slice::from_raw_parts(srm_ptr, srm_size as usize));
                }

                (self.adi_dispose)(mid_ptr);
                (self.adi_dispose)(srm_ptr);

                Ok(SynchronizeData { mid, srm })
            }
            err => Err(ADIError::resolve(err)),
        }
    }

    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError> {
        match (self.adi_provisioning_destroy)(session) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError> {
        let ptm_size = ptm.len() as u32;
        let ptm_ptr = ptm.as_ptr();

        let tk_size = tk.len() as u32;
        let tk_ptr = tk.as_ptr();

        match (self.adi_provisioning_end)(session, ptm_ptr, ptm_size, tk_ptr, tk_size) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn start_provisioning(
        &mut self,
        ds_id: i64,
        spim: &[u8],
    ) -> Result<StartProvisioningData, ADIError> {
        let spim_size = spim.len() as u32;
        let spim_ptr = spim.as_ptr();

        let mut cpim_size: u32 = 0;
        let mut cpim_ptr: *const u8 = std::ptr::null();

        let mut session: u32 = 0;

        match (self.adi_provisioning_start)(
            ds_id,
            spim_ptr,
            spim_size,
            &mut cpim_ptr,
            &mut cpim_size,
            &mut session,
        ) {
            0 => {
                let mut cpim = vec![0; cpim_size as usize];

                // SAFETY: This is safe as long as the library correctly initializes the data at
                // this locations - because it returned 0, we are trusting that it did.
                unsafe {
                    cpim.copy_from_slice(std::slice::from_raw_parts(cpim_ptr, cpim_size as usize));
                }

                (self.adi_dispose)(cpim_ptr);

                Ok(StartProvisioningData { cpim, session })
            }
            err => Err(ADIError::resolve(err)),
        }
    }

    fn is_machine_provisioned(&self, ds_id: i64) -> bool {
        (self.adi_get_login_code)(ds_id) == 0
    }

    fn request_otp(&self, ds_id: i64) -> Result<RequestOTPData, ADIError> {
        let mut mid_size: u32 = 0;
        let mut mid_ptr: *const u8 = std::ptr::null();
        let mut otp_size: u32 = 0;
        let mut otp_ptr: *const u8 = std::ptr::null();

        match (self.adi_otp_request)(
            ds_id,
            &mut mid_ptr,
            &mut mid_size,
            &mut otp_ptr,
            &mut otp_size,
        ) {
            0 => {
                let mut mid = vec![0; mid_size as usize];
                let mut otp = vec![0; otp_size as usize];

                // SAFETY: This is safe as long as the library returned initialized data at these
                // locations - because the function returned 0, we are trusting that it did.
                unsafe {
                    mid.copy_from_slice(std::slice::from_raw_parts(mid_ptr, mid_size as usize));
                    otp.copy_from_slice(std::slice::from_raw_parts(otp_ptr, otp_size as usize));
                }

                (self.adi_dispose)(mid_ptr);
                (self.adi_dispose)(otp_ptr);

                Ok(RequestOTPData { mid, otp })
            }
            err => Err(ADIError::resolve(err)),
        }
    }

    fn set_local_user_uuid(&mut self, local_user_uuid: String) {
        self.local_user_uuid = local_user_uuid;
    }

    fn set_device_identifier(&mut self, device_identifier: String) -> Result<()> {
        self.set_identifier(&device_identifier[0..16])?;
        self.device_identifier = device_identifier;
        Ok(())
    }

    fn get_local_user_uuid(&self) -> &str {
        self.local_user_uuid.as_str()
    }

    fn get_device_identifier(&self) -> &str {
        self.device_identifier.as_str()
    }

    fn get_serial_number(&self) -> &str {
        "0"
    }
}

impl ConfigurableADIProxy for StoreServicesCoreADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError> {
        match (self.adi_set_android_id)(identifier.as_ptr(), identifier.len() as u32) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }

    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError> {
        let path = CString::new(path).unwrap();
        match (self.adi_set_provisioning_path)(path.as_ptr() as *const u8) {
            0 => Ok(()),
            err => Err(ADIError::resolve(err)),
        }
    }
}

struct LoaderHelpers;

use rand::Rng;

#[cfg(all(target_family = "unix", not(target_os = "macos")))]
use libc::{
    chmod, close, free, fstat, ftruncate, gettimeofday, lstat, malloc, mkdir, open, read, strncpy,
    umask, write,
};
#[cfg(target_os = "macos")]
use posix_macos::*;

static mut ERRNO: i32 = 0;

#[allow(unreachable_code)]
#[sysv64]
unsafe fn __errno_location() -> *mut i32 {
    ERRNO = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    &mut ERRNO
}

#[sysv64]
fn arc4random() -> u32 {
    rand::thread_rng().gen()
}

#[sysv64]
unsafe fn __system_property_get(_name: *const c_char, value: *mut c_char) -> i32 {
    *value = '0' as c_char;
    return 1;
}

#[cfg(target_family = "windows")]
use posix_windows::*;

impl LoaderHelpers {
    pub fn setup_hooks() {
        let mut hooks = HashMap::new();
        hooks.insert("arc4random".to_owned(), arc4random as usize);
        hooks.insert("chmod".to_owned(), chmod as usize);
        hooks.insert(
            "__system_property_get".to_owned(),
            __system_property_get as usize,
        );
        hooks.insert("__errno".to_owned(), __errno_location as usize);
        hooks.insert("close".to_owned(), close as usize);
        hooks.insert("free".to_owned(), free as usize);
        hooks.insert("fstat".to_owned(), fstat as usize);
        hooks.insert("ftruncate".to_owned(), ftruncate as usize);
        hooks.insert("gettimeofday".to_owned(), gettimeofday as usize);
        hooks.insert("lstat".to_owned(), lstat as usize);
        hooks.insert("malloc".to_owned(), malloc as usize);
        hooks.insert("mkdir".to_owned(), mkdir as usize);
        hooks.insert("open".to_owned(), open as usize);
        hooks.insert("read".to_owned(), read as usize);
        hooks.insert("strncpy".to_owned(), strncpy as usize);
        hooks.insert("umask".to_owned(), umask as usize);
        hooks.insert("write".to_owned(), write as usize);

        hook_manager::add_hooks(hooks);
    }
}

#[derive(Debug)]
enum ADIStoreSericesCoreErr {
    InvalidLibraryFormat,
    Misc,
    MissingLibraries,
}

impl std::fmt::Display for ADIStoreSericesCoreErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ADIStoreSericesCoreErr {}

#[cfg(test)]
mod tests {
    use crate::{AnisetteConfiguration, AnisetteHeaders};
    use anyhow::Result;
    use log::info;
    use std::path::PathBuf;

    #[cfg(not(feature = "async"))]
    #[test]
    fn fetch_anisette_ssc() -> Result<()> {
        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_ssc_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers()?
        );
        Ok(())
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn fetch_anisette_ssc_async() -> Result<()> {
        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_ssc_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers().await?
        );
        Ok(())
    }
}
