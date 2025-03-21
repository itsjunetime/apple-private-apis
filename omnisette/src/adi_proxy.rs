use crate::adi_proxy::ProvisioningError::InvalidResponse;
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use anyhow::{Result, anyhow};
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use log::debug;
use plist::{Dictionary, Value};
use rand::RngCore;
#[cfg(not(feature = "async"))]
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue};
#[cfg(feature = "async")]
use reqwest::{Client, ClientBuilder, Response};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct ServerError {
    pub code: i64,
    pub description: String,
}

#[derive(Debug)]
pub enum ProvisioningError {
    InvalidResponse,
    ServerError(ServerError),
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProvisioningError {}

#[derive(Debug)]
pub enum ADIError {
    Unknown(i32),
    ProvisioningError(ProvisioningError),
}

impl ADIError {
    pub fn resolve(error_number: i32) -> ADIError {
        ADIError::Unknown(error_number)
    }
}

#[derive(Debug)]
enum ToPlistError {
	Plist(plist::Error),
	Bytes(reqwest::Error)
}

impl From<reqwest::Error> for ToPlistError {
	fn from(err: reqwest::Error) -> Self {
		Self::Bytes(err)
	}
}

impl From<plist::Error> for ToPlistError {
	fn from(err: plist::Error) -> Self {
		Self::Plist(err)
	}
}

impl std::fmt::Display for ToPlistError {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			ToPlistError::Bytes(err) => write!(fmt, "Error decoding from bytes: {err}"),
			ToPlistError::Plist(err) => write!(fmt, "Error decoding to plist: {err}"),
		}
	}
}

impl std::error::Error for ToPlistError {}

#[cfg_attr(feature = "async", async_trait::async_trait)]
trait ToPlist {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn plist(self) -> Result<Dictionary, ToPlistError>;
}

#[cfg_attr(feature = "async", async_trait::async_trait)]
impl ToPlist for Response {
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn plist(self) -> Result<Dictionary, ToPlistError> {
        Ok(Value::from_reader_xml(&*self.bytes().await?)
			.map(|list| list.as_dictionary().unwrap().to_owned())?)
    }
}

impl Display for ADIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ADIError {}

pub struct SynchronizeData {
    pub mid: Vec<u8>,
    pub srm: Vec<u8>,
}

pub struct StartProvisioningData {
    pub cpim: Vec<u8>,
    pub session: u32,
}

pub struct RequestOTPData {
    pub otp: Vec<u8>,
    pub mid: Vec<u8>,
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
pub trait ADIProxy {
    fn erase_provisioning(&mut self, ds_id: i64) -> Result<(), ADIError>;
    fn synchronize(&mut self, ds_id: i64, sim: &[u8]) -> Result<SynchronizeData, ADIError>;
    fn destroy_provisioning_session(&mut self, session: u32) -> Result<(), ADIError>;
    fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<(), ADIError>;
    fn start_provisioning(
        &mut self,
        ds_id: i64,
        spim: &[u8],
    ) -> Result<StartProvisioningData, ADIError>;
    fn is_machine_provisioned(&self, ds_id: i64) -> bool;
    fn request_otp(&self, ds_id: i64) -> Result<RequestOTPData, ADIError>;

    fn set_local_user_uuid(&mut self, local_user_uuid: String);
    fn set_device_identifier(&mut self, device_identifier: String) -> Result<()>;

    fn get_local_user_uuid(&self) -> &str;
    fn get_device_identifier(&self) -> &str;
    fn get_serial_number(&self) -> &str;
}

pub trait ConfigurableADIProxy: ADIProxy {
    fn set_identifier(&mut self, identifier: &str) -> Result<(), ADIError>;
    fn set_provisioning_path(&mut self, path: &str) -> Result<(), ADIError>;
}

pub const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
pub const CLIENT_INFO_HEADER: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
pub const DS_ID: i64 = -2;
pub const IDENTIFIER_LENGTH: usize = 16;
pub type Identifier = [u8; IDENTIFIER_LENGTH];

trait AppleRequestResult {
    fn check_status(&self) -> Result<()>;
    fn get_response(&self) -> Result<&Dictionary>;
}

impl AppleRequestResult for Dictionary {
    fn check_status(&self) -> Result<()> {
        let status = self
            .get("Status")
            .ok_or(InvalidResponse)?
            .as_dictionary()
            .unwrap();
        let code = status.get("ec").unwrap().as_signed_integer().unwrap();
        if code != 0 {
            let description = status.get("em").unwrap().as_string().unwrap().to_string();
            Err(ProvisioningError::ServerError(ServerError { code, description }).into())
        } else {
            Ok(())
        }
    }

    fn get_response(&self) -> Result<&Dictionary> {
        if let Some(response) = self.get("Response") {
            let response = response.as_dictionary().unwrap();
            response.check_status()?;
            Ok(response)
        } else {
            Err(InvalidResponse.into())
        }
    }
}

impl dyn ADIProxy {
    fn make_http_client(&mut self) -> Result<Client> {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_str("text/x-xml-plist")?);

        headers.insert(
            "X-Mme-Client-Info",
            HeaderValue::from_str(CLIENT_INFO_HEADER)?,
        );
        headers.insert(
            "X-Mme-Device-Id",
            HeaderValue::from_str(self.get_device_identifier())?,
        );
        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(self.get_local_user_uuid())?,
        );
        headers.insert(
            "X-Apple-I-SRL-NO",
            HeaderValue::from_str(self.get_serial_number())?,
        );

        debug!("Headers sent: {headers:?}");

        let http_client = ClientBuilder::new()
            .http1_title_case_headers()
            .danger_accept_invalid_certs(true) // TODO: pin the apple certificate
            .user_agent(AKD_USER_AGENT)
            .default_headers(headers)
            .build()?;

        Ok(http_client)
    }

    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn provision_device(&mut self) -> Result<()> {
        let client = self.make_http_client()?;

        let url_bag_res = client
            .get("https://gsa.apple.com/grandslam/GsService2/lookup")
            .send()
            .await
			.map_err(|e| anyhow!("Couldn't send lookup: {e}"))?
            .plist()
            .await
			.map_err(|e| anyhow!("Couldn't decode lookup response to a plist: {e}"))?;

        let urls = url_bag_res.get("urls").unwrap().as_dictionary().unwrap();

        let start_provisioning_url = urls
            .get("midStartProvisioning")
            .unwrap()
            .as_string()
            .unwrap();
        let finish_provisioning_url = urls
            .get("midFinishProvisioning")
            .unwrap()
            .as_string()
            .unwrap();

        let mut body = plist::Dictionary::new();
        body.insert(
            "Header".to_string(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );
        body.insert(
            "Request".to_string(),
            plist::Value::Dictionary(plist::Dictionary::new()),
        );

        let mut sp_request = Vec::new();
        plist::Value::Dictionary(body).to_writer_xml(&mut sp_request)?;

        debug!("First provisioning request...");
        let response = client
            .post(start_provisioning_url)
            .body(sp_request)
            .send()
            .await
			.map_err(|e| anyhow!("Couldn't send req to start provisioning at {start_provisioning_url}: {e}"))?
            .plist()
            .await
			.map_err(|e| anyhow!("Couldn't resolve start provisioning response to plist: {e}"))?;

        let response = response.get_response()?;

        let spim = response
            .get("spim")
            .unwrap()
            .as_string()
            .unwrap()
            .to_owned();

        let spim = base64_engine.decode(spim).map_err(|e| anyhow!("Couldn't decode spim to base64: {e}"))?;
        let first_step = self.start_provisioning(DS_ID, spim.as_slice())
			.map_err(|e| anyhow!("Couldn't start provision: {e}"))?;

        let mut body = Dictionary::new();
        let mut request = Dictionary::new();
        request.insert(
            "cpim".to_owned(),
            Value::String(base64_engine.encode(first_step.cpim)),
        );
        body.insert("Header".to_owned(), Value::Dictionary(Dictionary::new()));
        body.insert("Request".to_owned(), Value::Dictionary(request));

		println!("fp_req: {body:?}");

        let mut fp_request = Vec::new();
        Value::Dictionary(body).to_writer_xml(&mut fp_request)
			.map_err(|e| anyhow!("Couldn't write to xml: {e}"))?;

        debug!("Second provisioning request...");
        let response = client
            .post(finish_provisioning_url)
            .body(fp_request)
            .send()
            .await
			.map_err(|e| anyhow!("Couldn't send finish provisioning req to {finish_provisioning_url}: {e}"))?
            .plist()
            .await
			.map_err(|e| anyhow!("Couldn't decode finish provisioning req to plist: {e}"))?;

        let response = response.get_response()
			.map_err(|e| anyhow!("Couldn't get response from finish response: {e}"))?;

        let ptm = base64_engine.decode(response.get("ptm").unwrap().as_string().unwrap())
			.map_err(|e| anyhow!("Couldn't decode ptm from base64: {e}"))?;
        let tk = base64_engine.decode(response.get("tk").unwrap().as_string().unwrap())
			.map_err(|e| anyhow!("Couldn't decode tk from base64: {e}"))?;

        self.end_provisioning(first_step.session, ptm.as_slice(), tk.as_slice())
			.map_err(|e| anyhow!("Couldn't end provisioning: {e}"))?;
        debug!("Done.");

        Ok(())
    }
}

#[derive(Debug)]
pub enum NewADIProxyErr {
	IDFileUnopenable(String, std::io::Error),
	IDFileNoMetadata(std::io::Error),
	IDFileReadErr(std::io::Error),
	IDFileWriteErr(std::io::Error),
	FailedToSetDeviceID
}

impl Display for NewADIProxyErr {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		use NewADIProxyErr::*;
		match self {
			IDFileUnopenable(s, e) => write!(f, "The ID file specified at {s} was unopenable: {e}"),
			IDFileNoMetadata(e) => write!(f, "Could not retrieve metadata of ID file: {e}"),
			IDFileReadErr(e) => write!(f, "Error when reading ID from ID file: {e}"),
			IDFileWriteErr(e) => write!(f, "Error when writing to ID file: {e}"),
			FailedToSetDeviceID => write!(f, "Failed to set device identifier")
		}
	}
}

impl std::error::Error for NewADIProxyErr {}

pub struct ADIProxyAnisetteProvider<ProxyType: ADIProxy + 'static> {
    adi_proxy: ProxyType,
}

impl<ProxyType: ADIProxy + 'static> ADIProxyAnisetteProvider<ProxyType> {
    /// If you use this method, you are expected to set the identifier yourself.
    pub fn without_identifier(adi_proxy: ProxyType) -> Result<ADIProxyAnisetteProvider<ProxyType>> {
        Ok(ADIProxyAnisetteProvider { adi_proxy })
    }

    pub fn new(
        mut adi_proxy: ProxyType,
        configuration_path: PathBuf,
    ) -> Result<ADIProxyAnisetteProvider<ProxyType>, NewADIProxyErr> {
        let identifier_file_path = configuration_path.join("identifier");
        let mut identifier_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&identifier_file_path)
			.map_err(|e| NewADIProxyErr::IDFileUnopenable(format!("{identifier_file_path:?}"), e))?;
        let mut identifier = [0u8; IDENTIFIER_LENGTH];
        if identifier_file.metadata().map_err(NewADIProxyErr::IDFileNoMetadata)?.len() == IDENTIFIER_LENGTH as u64 {
            identifier_file.read_exact(&mut identifier).map_err(NewADIProxyErr::IDFileReadErr)?;
        } else {
            rand::thread_rng().fill_bytes(&mut identifier);
            identifier_file.write_all(&identifier).map_err(NewADIProxyErr::IDFileWriteErr)?;
        }

        let mut local_user_uuid_hasher = Sha256::new();
        local_user_uuid_hasher.update(identifier);

        adi_proxy.set_device_identifier(
            uuid::Uuid::from_bytes(identifier)
                .to_string()
                .to_uppercase(),
        ).map_err(|_| NewADIProxyErr::FailedToSetDeviceID)?; // UUID, uppercase
        adi_proxy
            .set_local_user_uuid(hex::encode(local_user_uuid_hasher.finalize()).to_uppercase()); // 64 uppercase character hex

        Ok(ADIProxyAnisetteProvider { adi_proxy })
    }

    pub fn adi_proxy(&mut self) -> &mut ProxyType {
        &mut self.adi_proxy
    }
}

#[cfg_attr(feature = "async", async_trait::async_trait(?Send))]
impl<ProxyType: ADIProxy + 'static> AnisetteHeadersProvider
    for ADIProxyAnisetteProvider<ProxyType>
{
    #[cfg_attr(not(feature = "async"), remove_async_await::remove_async_await)]
    async fn get_anisette_headers(
        &mut self,
        skip_provisioning: bool,
    ) -> Result<HashMap<String, String>> {
        let adi_proxy = &mut self.adi_proxy as &mut dyn ADIProxy;

        if !adi_proxy.is_machine_provisioned(DS_ID) && !skip_provisioning {
            adi_proxy.provision_device().await
				.map_err(|e| anyhow!("Couldn't provision: {e}"))?;
        }

        let machine_data = adi_proxy.request_otp(DS_ID)
			.map_err(|e| anyhow!("Couldn't request otp: {e}"))?;

        let mut headers = HashMap::new();
        headers.insert(
            "X-Apple-I-MD".to_string(),
            base64_engine.encode(machine_data.otp),
        );
        headers.insert(
            "X-Apple-I-MD-M".to_string(),
            base64_engine.encode(machine_data.mid),
        );
        headers.insert("X-Apple-I-MD-RINFO".to_string(), "17106176".to_string());
        headers.insert(
            "X-Apple-I-MD-LU".to_string(),
            adi_proxy.get_local_user_uuid().to_string(),
        );
        headers.insert(
            "X-Apple-I-SRL-NO".to_string(),
            adi_proxy.get_serial_number().to_string(),
        );
        headers.insert(
            "X-Mme-Client-Info".to_string(),
            CLIENT_INFO_HEADER.to_string(),
        );
        headers.insert(
            "X-Mme-Device-Id".to_string(),
            adi_proxy.get_device_identifier().to_string(),
        );

        Ok(headers)
    }
}
