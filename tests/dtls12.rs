use std::error::Error;

use network_parser_combinator::parser::Parser;
use network_parser_combinator::{dtls, tls};

// DTLS 1.2 session #1 payloads
static SERVER_HELLO_DONE_PAYLOAD: &str = "16fefd0000000000000002000c0e0000000002000000000000";

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
