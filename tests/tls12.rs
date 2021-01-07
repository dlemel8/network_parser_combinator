use std::error::Error;

use network_parser_combinator::parser::Parser;
use network_parser_combinator::tls;

// TLS 1.2 session payloads
static CLIENT_START_OF_HANDSHAKE_PAYLOAD: &str = "1603010087010000830303ab85fc5f6db67c9cf825cd8a1f34cf6c5e89ec09656a4944ec5536a36aed5728000004cca900ff0100005600000010000e00000b31302e34322e302e323433000b000403000102000a000a0008001d001700190018000d0020001e0403050306030804080508060401050106010203020102020402050206020016000000170000";
static SERVER_START_OF_HANDSHAKE_PAYLOAD: &str = "160303005d020000590303f76c185dff55f3931308b0d7f18d078e141ecd894b26efe15aabd5e0e7e45b3320c981b4588aacae50737272444755352b79c5bfba4fd95331691e5fd36cebb61dcca9000011ff01000100000b0004030001020017000016030301be0b0001ba0001b70001b4308201b030820135a003020102020900d2c6d38588184854300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3137303630323138333332385a170d3137303730323138333332385a30143112301006035504030c096c6f63616c686f73743076301006072a8648ce3d020106052b810400220362000418a4f5fe8fcca085378c7a37f1f349ab3dc19a3af6d539511df16db58875f4f0cf76cd43dd4ff235ec21d12c5f2f208d5ddc60c716d585e49a50b72a89d4cc61c9fa1156c2e217315c5f4396968ede55ec83f0ada7bedd3e57c947dc2114e6d1a3533051301d0603551d0e041604143fd86cb82d9cb88873e1699f35a0af07c450ff8e301f0603551d230418301680143fd86cb82d9cb88873e1699f35a0af07c450ff8e300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020369003066023100bcf4b27ad10e5f3bbfcf0e06e08e7b6d85250cafd32eff0ace9ab8bce30d9db8c76818849daa3a311924db4872cc937c023100a354d9ba25e978b7544914fe453f813bcea7ab5cfd5edb58b8b2e6cb24c91334bfd3ba85abe294bb8f7d7e950da6e12016030300920c00008e03001d205e2b666dd7125255cf5e0ff859d8f97e5f86fd6a0f16a8575c15a9f461617f4f040300663064023059632b3ebf0dd42ced5527df9e0b918052c8c1cb6d5f5fbfa536ce64b08c1f46022fb55d7865bce13405c381555f80960230667286ab5dca3b5b96bf3c78e15bc4ab628faff45d6dd2df5e7ed2df793e9a1438f49225ab3ea058f594826b27f2723716030300040e000000";
static CLIENT_END_OF_HANDSHAKE_PAYLOAD: &str = "1603030025100000212043dcf44cc39c33ce2cda1a1a5106f249506d7519cdd1cb88b15f3594ca78277a14030300010116030300208e6041083b89ff49d068ec2f735d9dd8da0e286b5f9b84b135be0e4cf538c409";
static SERVER_END_OF_HANDSHAKE_PAYLOAD: &str = "1403030001011603030020b5abee4e71b1dfd471e32c279d8f25d82279c5082707d6e33992ec94893af2bd";
static ENCRYPTED_APPLICATION_DATA: &str = "17030300335764dd7e195832563e2ba206e773b683481e6c561c3db4ec33e8f1d7deedf5d55b592283a026ff7939cf5d6848207bd652f1cb";
static ENCRYPTED_ALERT: &str = "15030300129a6ccaf17f9b90b07284170435c3e565cdff";

#[test]
fn tls_parser_client_start_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(CLIENT_START_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.0".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ClientHello(
                "1.2".to_string(),
                2,
                1,
                vec![
                    tls::Extension::ServerName,
                    tls::Extension::EcPointFormats,
                    tls::Extension::SupportedGroups,
                    tls::Extension::SignatureAlgorithms,
                    tls::Extension::EncryptThenMac,
                    tls::Extension::ExtendedMasterSecret,
                ],
            )),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_server_start_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_START_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(4..5);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ServerHello(
                "1.2".to_string(),
                vec![
                    tls::Extension::RenegotiationInfo,
                    tls::Extension::EcPointFormats,
                    tls::Extension::ExtendedMasterSecret,
                ],
            )),
        },
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Certificate),
        },
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ServerKeyExchange),
        },
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ServerHelloDone),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_client_end_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(CLIENT_END_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(3..4);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ClientKeyExchange),
        },
        tls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Encrypted(&[142, 96, 65, 8, 59, 137, 255, 73, 208, 104, 236, 47, 115, 93, 157, 216, 218, 14, 40, 107, 95, 155, 132, 177, 53, 190, 14, 76, 245, 56, 196, 9])),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_server_end_of_handshake() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(SERVER_END_OF_HANDSHAKE_PAYLOAD).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(2..3);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        },
        tls::Record {
            content_type: tls::ContentType::Handshake,
            version: "1.2".to_string(),
            data: tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Encrypted(&[181, 171, 238, 78, 113, 177, 223, 212, 113, 227, 44, 39, 157, 143, 37, 216, 34, 121, 197, 8, 39, 7, 214, 227, 57, 146, 236, 148, 137, 58, 242, 189])),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_encrypted_application_data() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(ENCRYPTED_APPLICATION_DATA).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[87, 100, 221, 126, 25, 88, 50, 86, 62, 43, 162, 6, 231, 115, 182, 131, 72, 30, 108, 86, 28, 61, 180, 236, 51, 232, 241, 215, 222, 237, 245, 213, 91, 89, 34, 131, 160, 38, 255, 121, 57, 207, 93, 104, 72, 32, 123, 214, 82, 241, 203]),
        }
    ], records.parsed);
    Ok(())
}

#[test]
fn tls_parser_encrypted_alert() -> Result<(), Box<dyn Error>> {
    let payload = hex::decode(ENCRYPTED_ALERT).expect("failed to decode payload");
    let parser = tls::record_parser().repeat(1..2);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    assert_eq!(vec![
        tls::Record {
            content_type: tls::ContentType::Alert,
            version: "1.2".to_string(),
            data: tls::Data::Encrypted(&[154, 108, 202, 241, 127, 155, 144, 176, 114, 132, 23, 4, 53, 195, 229, 101, 205, 255]),
        }
    ], records.parsed);
    Ok(())
}