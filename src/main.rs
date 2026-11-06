//! Native messaging helper for Towa: answers a passkey request from the
//! Microsoft sign-in page with a passkey kept on a phone, over the FIDO
//! hybrid transport (QR code, Bluetooth proximity check, then a tunnel
//! through the phone vendor's relay server).
//!
//! Towa sends one message, {"origin": ..., "options": ...}, where options is
//! the PublicKeyCredentialRequestOptionsJSON of the page. The helper answers
//! with {"qr": svg}, then {"status": ...} updates, and finally either
//! {"credential": AuthenticationResponseJSON} or {"error": text}. Closing the
//! port cancels the request.

use std::error::Error;
use std::io::Write as _;
use std::time::Duration;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, JsonFormat, OriginValidation, RequestOrigin, RequestSettings,
    WebAuthnIDLResponse as _,
};
use libwebauthn::transport::hybrid::channel::{HybridUxUpdate, PxpUpdate};
use libwebauthn::transport::hybrid::is_available;
use libwebauthn::transport::hybrid::qr_code_device::{
    PxpQrCodeDevice, PxpTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::{WebAuthn as _, WebAuthnError};
use libwebauthn::UvUpdate;
use qrcode::render::svg;
use qrcode::QrCode;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// The only page the helper signs for. Entra ID passkeys are registered
/// for this relying party, and a browser would refuse any other origin.
const ORIGIN: &str = "https://login.microsoft.com";
const RP_ID: &str = "login.microsoft.com";

/// Requests are a few hundred bytes, anything much larger is not from Towa.
const MAX_REQUEST: usize = 64 * 1024;

/// The page picks the timeout. Keep it long enough to scan the QR code and
/// short enough not to wait for a phone that never answers.
const MIN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TIMEOUT: Duration = Duration::from_secs(600);

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Native messaging framing: a 32-bit length in native byte order, then the
/// JSON text.
fn send(message: &Value) {
    let text = message.to_string();
    let mut out = std::io::stdout().lock();
    let length = u32::try_from(text.len()).expect("message too large");
    // A write error means Thunderbird closed the port, so there is nobody
    // left to tell.
    if out.write_all(&length.to_ne_bytes()).is_err()
        || out.write_all(text.as_bytes()).is_err()
        || out.flush().is_err()
    {
        std::process::exit(0);
    }
}

async fn receive(input: &mut (impl AsyncRead + Unpin)) -> Result<Value> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length).await?;
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_REQUEST {
        return Err("request too large".into());
    }
    let mut text = vec![0u8; length];
    input.read_exact(&mut text).await?;
    Ok(serde_json::from_slice(&text)?)
}

async fn prepare(message: &Value) -> Result<GetAssertionRequest> {
    if message["origin"].as_str() != Some(ORIGIN) {
        return Err("origin not allowed".into());
    }
    let origin: RequestOrigin = ORIGIN.try_into().map_err(|_| "invalid origin")?;
    // The origin is fixed above, so the rp id check only has to accept the
    // one relying party below.
    let settings = RequestSettings {
        origin: OriginValidation::Trust,
    };
    let mut request =
        GetAssertionRequest::prepare(&origin, &message["options"].to_string(), &settings)
            .await
            .map_err(|err| format!("invalid request: {err}"))?;
    if request.relying_party_id != RP_ID {
        return Err("relying party not allowed".into());
    }
    request.timeout = request.timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    Ok(request)
}

fn status(update: HybridUxUpdate) -> Option<&'static str> {
    match update {
        HybridUxUpdate::PxpUpdate(PxpUpdate::ProximityCheck) => Some("proximity"),
        HybridUxUpdate::PxpUpdate(PxpUpdate::Connecting) => Some("connecting"),
        HybridUxUpdate::PxpUpdate(PxpUpdate::Authenticating) => Some("authenticating"),
        HybridUxUpdate::PxpUpdate(PxpUpdate::Connected) => Some("connected"),
        HybridUxUpdate::UvUpdate(UvUpdate::PresenceRequired) => Some("confirm"),
        _ => None,
    }
}

async fn sign(request: &GetAssertionRequest) -> Result<Value> {
    if !is_available().await {
        return Err("no Bluetooth adapter".into());
    }
    let mut device = PxpQrCodeDevice::new_transient(
        QrCodeOperationHint::GetAssertionRequest,
        PxpTransports::CloudAssistedOrLocal,
    )?;
    let qr = QrCode::new(device.qr_code.to_string())?
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .build();
    send(&json!({ "qr": qr }));

    let mut channel = device.channel(ChannelSettings::default()).await?;
    let mut updates = channel.get_ux_update_receiver();
    tokio::spawn(async move {
        while let Ok(update) = updates.recv().await {
            if let Some(text) = status(update) {
                send(&json!({ "status": text }));
            }
        }
    });

    // Phones hang up after one command, so a failed request is not retried.
    let response = channel.webauthn_get_assertion(request).await;
    channel.close().await;
    let assertion = response
        .map_err(|err| match err {
            // The adapter is found even when it is powered off.
            WebAuthnError::Transport(_) => {
                format!("passkey request failed, check that Bluetooth is on: {err}")
            }
            _ => format!("passkey request failed: {err}"),
        })?
        .assertions
        .into_iter()
        .next()
        .ok_or("the phone sent no passkey")?;
    let credential = assertion
        .to_json_string(request, JsonFormat::Minified)
        .map_err(|err| format!("invalid answer: {err}"))?;
    Ok(serde_json::from_str(&credential)?)
}

#[tokio::main]
async fn main() {
    let mut input = tokio::io::stdin();
    let result = match receive(&mut input).await {
        Ok(message) => match prepare(&message).await {
            Ok(request) => {
                // Thunderbird closes stdin when Towa gives up, which cancels
                // the request.
                tokio::spawn(async move {
                    let mut rest = [0u8; 256];
                    while matches!(input.read(&mut rest).await, Ok(n) if n > 0) {}
                    std::process::exit(0);
                });
                match tokio::time::timeout(request.timeout, sign(&request)).await {
                    Ok(result) => result,
                    Err(_) => Err("timed out".into()),
                }
            }
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    };
    match result {
        Ok(credential) => send(&json!({ "credential": credential })),
        Err(err) => send(&json!({ "error": err.to_string() })),
    }
    // Leave without waiting for the stdin read above, which cannot be
    // cancelled and would keep the runtime from shutting down.
    std::process::exit(0);
}
