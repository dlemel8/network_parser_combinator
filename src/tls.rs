use crate::general::{byte_parser, size_header_parser};
use crate::parser::{one_of, Parser, ParserResult};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
}

fn content_type_parser<'a>() -> impl Parser<'a, ContentType> {
    one_of(vec![
        byte_parser(20).map(|_| { ContentType::ChangeCipherSpec }),
        byte_parser(21).map(|_| { ContentType::Alert }),
        byte_parser(22).map(|_| { ContentType::Handshake }),
        byte_parser(23).map(|_| { ContentType::ApplicationData }),
        byte_parser(24).map(|_| { ContentType::Heartbeat }),
    ])
}

type Version = String;

fn version_parser<'a>() -> impl Parser<'a, Version> {
    byte_parser(3).then(|_| {
        one_of(vec![
            byte_parser(1), byte_parser(2), byte_parser(3), byte_parser(4),
        ])
            .map(|x| { format!("1.{}", x - 1) })
    })
}

#[derive(Debug, PartialEq)]
pub enum ExtensionType {
    ServerName,
    MaxFragmentLength,
    ClientCertificate,
    TrustedCaKeys,
    TruncatedHMac,
    StatusRequest,
    UserMapping,
    ClientAuthz,
    ServerAuthz,
    CertType,
    SupportedGroups,
    EcPointFormats,
    Srp,
    SignatureAlgorithms,
    UseSrtp,
    Heartbeat,
    ApplicationLayerProtocolNegotiation,
    StatusRequestV2,
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    EncryptThenMac,
    ExtendedMasterSecret,
    TokenBinding,
    CachedInfo,
    RecordSizeLimit,
    SessionTicketTLS,
    SupportedVersions,
    PskExchangeModes,
    KeyShare,
    RenegotiationInfo,
}

fn extension_type_parser<'a>() -> impl Parser<'a, ExtensionType> {
    one_of(vec![
        byte_parser(0).and(byte_parser(0)).map(|_| { ExtensionType::ServerName }),
        byte_parser(0).and(byte_parser(1)).map(|_| { ExtensionType::MaxFragmentLength }),
        byte_parser(0).and(byte_parser(2)).map(|_| { ExtensionType::ClientCertificate }),
        byte_parser(0).and(byte_parser(3)).map(|_| { ExtensionType::TrustedCaKeys }),
        byte_parser(0).and(byte_parser(4)).map(|_| { ExtensionType::TruncatedHMac }),
        byte_parser(0).and(byte_parser(5)).map(|_| { ExtensionType::StatusRequest }),
        byte_parser(0).and(byte_parser(6)).map(|_| { ExtensionType::UserMapping }),
        byte_parser(0).and(byte_parser(7)).map(|_| { ExtensionType::ClientAuthz }),
        byte_parser(0).and(byte_parser(8)).map(|_| { ExtensionType::ServerAuthz }),
        byte_parser(0).and(byte_parser(9)).map(|_| { ExtensionType::CertType }),
        byte_parser(0).and(byte_parser(0xa)).map(|_| { ExtensionType::SupportedGroups }),
        byte_parser(0).and(byte_parser(0xb)).map(|_| { ExtensionType::EcPointFormats }),
        byte_parser(0).and(byte_parser(0xc)).map(|_| { ExtensionType::Srp }),
        byte_parser(0).and(byte_parser(0xd)).map(|_| { ExtensionType::SignatureAlgorithms }),
        byte_parser(0).and(byte_parser(0xe)).map(|_| { ExtensionType::UseSrtp }),
        byte_parser(0).and(byte_parser(0xf)).map(|_| { ExtensionType::Heartbeat }),
        byte_parser(0).and(byte_parser(0x10)).map(|_| { ExtensionType::ApplicationLayerProtocolNegotiation }),
        byte_parser(0).and(byte_parser(0x11)).map(|_| { ExtensionType::StatusRequestV2 }),
        byte_parser(0).and(byte_parser(0x12)).map(|_| { ExtensionType::SignedCertificateTimestamp }),
        byte_parser(0).and(byte_parser(0x13)).map(|_| { ExtensionType::ClientCertificateType }),
        byte_parser(0).and(byte_parser(0x14)).map(|_| { ExtensionType::ServerCertificateType }),
        byte_parser(0).and(byte_parser(0x15)).map(|_| { ExtensionType::Padding }),
        byte_parser(0).and(byte_parser(0x16)).map(|_| { ExtensionType::EncryptThenMac }),
        byte_parser(0).and(byte_parser(0x17)).map(|_| { ExtensionType::ExtendedMasterSecret }),
        byte_parser(0).and(byte_parser(0x18)).map(|_| { ExtensionType::TokenBinding }),
        byte_parser(0).and(byte_parser(0x19)).map(|_| { ExtensionType::CachedInfo }),
        byte_parser(0).and(byte_parser(0x1c)).map(|_| { ExtensionType::RecordSizeLimit }),
        byte_parser(0).and(byte_parser(0x23)).map(|_| { ExtensionType::SessionTicketTLS }),
        byte_parser(0).and(byte_parser(0x2b)).map(|_| { ExtensionType::SupportedVersions }),
        byte_parser(0).and(byte_parser(0x2d)).map(|_| { ExtensionType::PskExchangeModes }),
        byte_parser(0).and(byte_parser(0x33)).map(|_| { ExtensionType::KeyShare }),
        byte_parser(0xff).and(byte_parser(1)).map(|_| { ExtensionType::RenegotiationInfo }),
    ])
}

#[derive(Debug, PartialEq)]
pub struct Extension {
    pub type_: ExtensionType
}

fn extension_parser<'a>() -> impl Parser<'a, Extension> {
    extension_type_parser()
        .and(size_header_parser(2, true))
        .map(|(extension_type, _)| { Extension { type_: extension_type } })
}

type CipherSuitesCount = usize;
type CompressionMethodsCount = usize;

#[derive(Debug, PartialEq)]
pub enum HandshakeProtocol<'a> {
    ClientHello(Version, CipherSuitesCount, CompressionMethodsCount, Vec<Extension>),
    ServerHello(Version, Vec<Extension>),
    Certificate,
    ServerKeyExchange,
    ServerHelloDone,
    ClientKeyExchange,
    Encrypted(&'a [u8]),
}

fn client_hello_parser<'a>() -> impl Parser<'a, HandshakeProtocol<'a>> {
    version_parser()
        .skip(32)// random
        .and(size_header_parser(1, true)) // session id
        .and(size_header_parser(2, true)) // cipher suites
        .and(size_header_parser(1, true)) // compression methods
        .and(size_header_parser(2, false))// extensions
        .then(|((((version, _), size1), size2), size3)|
            extension_parser().repeat(..=size3)
                .map(move |extensions| {
                    HandshakeProtocol::ClientHello(version.clone(), size1 / 2, size2, extensions)
                })
                .skip_to(size3)
        )
}

fn server_hello_parser<'a>() -> impl Parser<'a, HandshakeProtocol<'a>> {
    version_parser()
        .skip(32)   // random
        .and(size_header_parser(1, true)) // session id
        .skip(3)// cipher suite + compression method
        .and(size_header_parser(2, false))// extensions
        .then(|((version, _), size)|
            extension_parser().repeat(..=size)
                .map(move |extensions| { HandshakeProtocol::ServerHello(version.clone(), extensions) })
                .skip_to(size)
        )
}

fn handshake_parser<'a>() -> impl Parser<'a, HandshakeProtocol<'a>> {
    move |input: &'a [u8]| {
        if input.is_empty() {
            return Err("nothing to parse".to_string());
        }

        one_of(vec![
            byte_parser(1)
                .and(size_header_parser(3, false))
                .then(|(_, size)| client_hello_parser().skip_to(size)),
            byte_parser(2)
                .and(size_header_parser(3, false))
                .then(|(_, size)| server_hello_parser().skip_to(size)),
            one_of(vec![
                byte_parser(11).map(|_| { HandshakeProtocol::Certificate }),
                byte_parser(12).map(|_| { HandshakeProtocol::ServerKeyExchange }),
                byte_parser(14).map(|_| { HandshakeProtocol::ServerHelloDone }),
                byte_parser(16).map(|_| { HandshakeProtocol::ClientKeyExchange }),
            ])
                .and(size_header_parser(3, true))
                .map(|(handshake, _)| { handshake }),
        ])
            .parse(&input)
            .or_else(|_| {
                Ok(ParserResult {
                    parsed: HandshakeProtocol::Encrypted(&input),
                    remaining: &input[input.len()..],
                })
            })
    }
}

#[derive(Debug, PartialEq)]
pub enum Data<'a> {
    HandshakeProtocol(HandshakeProtocol<'a>),
    ChangeCipherSpec,
    Encrypted(&'a [u8]),
}

fn data_parser<'a>(content_type: ContentType) -> impl Parser<'a, Data<'a>> {
    move |input: &'a [u8]| {
        match content_type {
            ContentType::ChangeCipherSpec =>
                byte_parser(1)
                    .map(|_| { Data::ChangeCipherSpec })
                    .parse(&input),
            ContentType::Handshake =>
                handshake_parser()
                    .map(|handshake| { Data::HandshakeProtocol(handshake) })
                    .parse(&input),
            _ => Ok(ParserResult {
                parsed: Data::Encrypted(&input),
                remaining: &input[input.len()..],
            })
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Record<'a> {
    pub content_type: ContentType,
    pub version: String,
    pub data: Data<'a>,
}

pub fn record_parser<'a>() -> impl Parser<'a, Record<'a>> {
    content_type_parser()
        .and(version_parser())
        .and(size_header_parser(2, false))
        .then(|((content_type, version), size)| {
            data_parser(content_type)
                .map(move |data| { Record { content_type, version: version.clone(), data } })
                .skip_to(size)
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::parser::Parser;
    use crate::tls;

    #[test]
    fn content_type_parser_on_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::content_type_parser().parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_unknown_value_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls::content_type_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_known_value_return_content_type() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [22, 2, 3];
        let result = tls::content_type_parser().parse(&input)?;
        assert_eq!(tls::ContentType::Handshake, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn version_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [1];
        let result = tls::version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_unknown_value_return_version() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 7];
        let result = tls::version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_known_value_return_it() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls::version_parser().parse(&input)?;
        assert_eq!("1.2", result.parsed);
        assert_eq!([7], result.remaining);
        Ok(())
    }

    #[test]
    fn extension_type_parser_on_input_with_unknown_value_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls::extension_type_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn extension_type_parser_on_input_with_known_value_return_extension_type() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 0x18, 3];
        let result = tls::extension_type_parser().parse(&input)?;
        assert_eq!(tls::ExtensionType::TokenBinding, result.parsed);
        assert_eq!([3], result.remaining);
        Ok(())
    }

    #[test]
    fn extension_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 8, 3];
        let result = tls::extension_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn extension_parser_on_input_with_known_value_return_content_type() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [0, 8, 0, 1, 1, 2, 3];
        let result = tls::extension_parser().parse(&input)?;
        assert_eq!(tls::Extension { type_: tls::ExtensionType::ServerAuthz }, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn client_hello_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 40];
        input[0] = 3;
        input[1] = 3;
        input[39] = 3;
        let result = tls::client_hello_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn client_hello_parser_on_valid_no_extension_input_return_handshake() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 40];
        input[0] = 3;
        input[1] = 3;
        let empty: Vec<tls::Extension> = vec![];
        let result = tls::client_hello_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ClientHello("1.2".to_string(), 0, 0, empty), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn client_hello_parser_on_valid_with_extension_input_return_handshake() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 50];
        input[0] = 3;
        input[1] = 3;
        input[36] = 2;
        input[39] = 2;
        input[43] = 4;
        let result = tls::client_hello_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ClientHello(
            "1.2".to_string(), 1, 2,
            vec![tls::Extension { type_: tls::ExtensionType::ServerName }],
        ), result.parsed);
        assert_eq!([0;2], result.remaining);
        Ok(())
    }

    #[test]
    fn server_hello_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 40];
        input[0] = 3;
        input[1] = 3;
        input[39] = 3;
        let result = tls::server_hello_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn server_hello_parser_on_valid_no_extension_input_return_handshake() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 45];
        input[0] = 3;
        input[1] = 3;
        input[39] = 3;
        let empty: Vec<tls::Extension> = vec![];
        let result = tls::server_hello_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ServerHello("1.2".to_string(), empty), result.parsed);
        assert_eq!([0; 2], result.remaining);
        Ok(())
    }

    #[test]
    fn server_hello_parser_on_valid_with_extension_input_return_handshake() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 46];
        input[0] = 3;
        input[1] = 3;
        input[39] = 4;
        input[41] = 0x17;
        let result = tls::server_hello_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ServerHello(
            "1.2".to_string(),
            vec![tls::Extension { type_: tls::ExtensionType::ExtendedMasterSecret }],
        ), result.parsed);
        assert_eq!([0; 2], result.remaining);
        Ok(())
    }

    #[test]
    fn handshake_parser_on_not_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::handshake_parser().parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_unknown_type_return_encrypted_handshake() -> Result<(), Box<dyn Error>> {
        let input: [u8; 4] = [88, 1, 3, 4];
        let result = tls::handshake_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::Encrypted(&[88, 1, 3, 4]), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_known_type_return_specific_handshake() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [12, 0, 0, 1, 1, 3, 4];
        let result = tls::handshake_parser().parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ServerKeyExchange, result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_encrypted_content_type_return_data_with_all_input() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls::data_parser(tls::ContentType::Heartbeat).parse(&input)?;
        assert_eq!(tls::Data::Encrypted(&input), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec).parse(b"a");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec).parse(&input)?;
        assert_eq!(tls::Data::ChangeCipherSpec, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::data_parser(tls::ContentType::Handshake).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [16, 0, 0, 1, 1, 2, 3];
        let result = tls::data_parser(tls::ContentType::Handshake).parse(&input)?;
        assert_eq!(tls::Data::HandshakeProtocol(tls::HandshakeProtocol::ClientKeyExchange), result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn record_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 2, 0, 10, 100, 5, 14, 2];
        let result = tls::record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 100, 0, 2, 100, 5, 14, 2];
        let result = tls::record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_valid_application_input_return_record() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 2, 0, 2, 100, 5, 14, 2];
        let result = tls::record_parser().parse(&input)?;
        let expected = tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.1".to_string(),
            data: tls::Data::Encrypted(&[100, 5]),
        };
        assert_eq!(expected, result.parsed);
        assert_eq!([14, 2], result.remaining);
        Ok(())
    }

    #[test]
    fn record_parser_on_valid_change_cipher_spec_input_return_record() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [20, 3, 1, 0, 1, 1, 5, 14, 2];
        let result = tls::record_parser().parse(&input)?;
        let expected = tls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.0".to_string(),
            data: tls::Data::ChangeCipherSpec,
        };
        assert_eq!(expected, result.parsed);
        assert_eq!([5, 14, 2], result.remaining);
        Ok(())
    }
}