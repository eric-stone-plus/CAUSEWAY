//! First-byte protocol classification.
//!
//! Design constraint "explicit over clever": no SNI sniffing, target parsing,
//! or general-purpose rule engine — only the first byte is inspected: a
//! SOCKS5 handshake starts with 0x05; an HTTP method (GET/CONNECT/...) starts
//! with an ASCII letter. Static exact-host routing, when configured, belongs
//! to the supervised adapter rather than this classifier.
//! The classification result is used only to choose sslocal's socks / http
//! local port; afterwards it is byte-for-byte L4 passthrough.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProto {
    Socks5,
    Http,
}

#[derive(Debug, Error)]
pub enum PeekError {
    #[error("peer closed the connection before sending any bytes")]
    Eof,
    #[error("timed out waiting for the first byte")]
    Timeout,
    #[error("unrecognized first byte: {0:#04x} (neither SOCKS5 nor HTTP)")]
    Unknown(u8),
}

/// Determine the inbound protocol from the first byte.
pub fn classify(first: u8) -> Result<InboundProto, PeekError> {
    if first == 0x05 {
        Ok(InboundProto::Socks5)
    } else if first.is_ascii_alphabetic() {
        Ok(InboundProto::Http)
    } else {
        Err(PeekError::Unknown(first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_handshake_byte() {
        assert_eq!(classify(0x05).unwrap(), InboundProto::Socks5);
    }

    #[test]
    fn http_methods() {
        for m in [
            "GET", "CONNECT", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "PATCH",
        ] {
            assert_eq!(
                classify(m.as_bytes()[0]).unwrap(),
                InboundProto::Http,
                "{m}"
            );
        }
    }

    #[test]
    fn unknown_bytes_rejected() {
        // SOCKS4 is 0x04, explicitly unsupported (explicit over clever: no guessing)
        assert!(matches!(classify(0x04), Err(PeekError::Unknown(0x04))));
        assert!(matches!(classify(0x00), Err(PeekError::Unknown(0x00))));
        assert!(matches!(classify(0x16), Err(PeekError::Unknown(0x16)))); // TLS ClientHello
    }
}
