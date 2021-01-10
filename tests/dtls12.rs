use std::error::Error;

use network_parser_combinator::parser::Parser;
use network_parser_combinator::{dtls, tls};

// DTLS 1.2 session #1 payloads
static SERVER_HELLO_DONE_PAYLOAD: &str = "16fefd0000000000000002000c0e0000000002000000000000";
static CLIENT_END_OF_HANDSHAKE_PAYLOAD: &str = "16fefd0000000000000002001210000006000200000000000600047465737414fefd000000000000000300010116fefd0001000000000000002800010000000000006540080120371f2ea6aa2bc268161620c792f47021205e56a0b64f34ee4b27b0";
static SERVER_CHANGE_CIPHER_SPEC_PAYLOAD: &str = "14fefd0000000000000003000101";
static SERVER_ENCRYPTED_HANDSHAKE_PAYLOAD: &str = "16fefd0001000000000000002800010000000000004dd9e249e86b60a5811b9f002123eb0ec23b260587d25b07fae6691f2a99e28d";
static ENCRYPTED_APPLICATION_DATA: &str = "17fefd000100000000000100300001000000000001c2315fbaace18d75d6220ca5fb6d978216d736c454f287b518743b2b32013f33ce62ab214c2a0b9c";
static ENCRYPTED_ALERT: &str = "15fefd000100000000000300120001000000000003d2aa4f0a3362fee37b72";

#[test]
fn dtls_parser_server_hello_done() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_HELLO_DONE_PAYLOAD).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ServerHelloDone),
        },
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_client_end_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(CLIENT_END_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(3..4);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ClientKeyExchange),
        },
        dtls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
        dtls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Encrypted(&[0, 1, 0, 0, 0, 0, 0, 0, 101, 64, 8, 1, 32, 55, 31, 46, 166, 170, 43, 194, 104, 22, 22, 32, 199, 146, 244, 112, 33, 32, 94, 86, 160, 182, 79, 52, 238, 75, 39, 176])),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn dtls_parser_server_change_cipher_spec() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_CHANGE_CIPHER_SPEC_PAYLOAD).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
    ], records.parsed);
    Ok(())
}

#[test]
fn dtls_parser_server_encrypted_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_ENCRYPTED_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Encrypted(&[0, 1, 0, 0, 0, 0, 0, 0, 77, 217, 226, 73, 232, 107, 96, 165, 129, 27, 159, 0, 33, 35, 235, 14, 194, 59, 38, 5, 135, 210, 91, 7, 250, 230, 105, 31, 42, 153, 226, 141])),
        },
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_encrypted_application_data() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(ENCRYPTED_APPLICATION_DATA).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[0, 1, 0, 0, 0, 0, 0, 1, 194, 49, 95, 186, 172, 225, 141, 117, 214, 34, 12, 165, 251, 109, 151, 130, 22, 215, 54, 196, 84, 242, 135, 181, 24, 116, 59, 43, 50, 1, 63, 51, 206, 98, 171, 33, 76, 42, 11, 156]),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_encrypted_alert() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(ENCRYPTED_ALERT).expect("failed to decode payload");
    let parser = dtls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        dtls::Record {
            content_type: tls::ContentType::Alert,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[0, 1, 0, 0, 0, 0, 0, 3, 210, 170, 79, 10, 51, 98, 254, 227, 123, 114]),
        }
    ], records.parsed);
    Ok(())
}