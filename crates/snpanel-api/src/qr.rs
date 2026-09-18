//! The 2FA enrolment QR code.
//!
//! Source: `_qr_data_url`, which is `qrcode.make(uri)` rendered to PNG and
//! base64'd into a `data:` URL the SPA puts straight in an `<img>`.
//!
//! The bytes are not expected to be identical to Pillow's - a PNG encoder is
//! free to choose its own filtering and compression - and NT7 does not ask for
//! that. What has to match is the *shape* (`data:image/png;base64,...`) and,
//! far more importantly, what the image says: scanning it must yield the same
//! `otpauth://` URI, or the user enrols a secret the panel will not accept.
//!
//! `qrcode.make` defaults to error correction M and a four-module quiet zone,
//! so those are set explicitly here rather than left to this crate's defaults.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use qrcode::{EcLevel, QrCode};

/// Ten pixels a module, as `qrcode.make`'s `box_size=10`.
const MODULE_PIXELS: u32 = 10;
// The quiet zone is the renderer's own, not forced through `min_dimensions`:
// a minimum size makes the renderer *shrink the modules* to fit, which is how
// an earlier version of this file produced a 111-pixel image where Python
// produces a ~370-pixel one. Still a valid QR, but small enough that phone
// cameras struggle with it.

/// Render `uri` as a PNG data URL, or an empty string if it cannot be encoded.
pub fn data_url(uri: &str) -> String {
    match render_png(uri) {
        Some(png) => format!("data:image/png;base64,{}", STANDARD.encode(png)),
        None => {
            // An unencodable URI is not worth failing the whole enrolment over:
            // the secret and the otpauth:// URI are both in the same response,
            // so the user can still type them in by hand.
            tracing::error!("could not render the enrolment QR code");
            String::new()
        }
    }
}

fn render_png(uri: &str) -> Option<Vec<u8>> {
    let code = QrCode::with_error_correction_level(uri, EcLevel::M).ok()?;
    let image = code
        .render::<image::Luma<u8>>()
        .module_dimensions(MODULE_PIXELS, MODULE_PIXELS)
        .quiet_zone(true)
        .build();

    let mut out = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut out, image::ImageFormat::Png)
        .ok()
        .map(|()| out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uri_renders_to_a_png_data_url() {
        let url = data_url(
            "otpauth://totp/SNPanel:admin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=SNPanel",
        );
        assert!(
            url.starts_with("data:image/png;base64,"),
            "{}",
            &url[..40.min(url.len())]
        );

        let encoded = url.trim_start_matches("data:image/png;base64,");
        let png = STANDARD.decode(encoded).expect("valid base64");
        // The PNG magic number, so this is an image and not an error page.
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        assert!(png.len() > 100, "a real QR is not a handful of bytes");
    }

    #[test]
    fn the_image_is_large_enough_to_scan() {
        // Ten pixels a module with a four-module border, as Python renders it.
        let png = render_png("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").expect("renders");
        let decoded = image::load_from_memory(&png).expect("decodes");
        assert!(
            decoded.width() >= 200 && decoded.height() >= 200,
            "{}x{} is too small to scan reliably",
            decoded.width(),
            decoded.height()
        );
        assert_eq!(decoded.width(), decoded.height(), "a QR is square");
    }

    #[test]
    fn an_empty_uri_does_not_panic() {
        // Whatever comes back, the enrolment response must still be sendable.
        let _ = data_url("");
    }
}
