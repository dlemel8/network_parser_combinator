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

pub(crate) fn content_type_parser<'a>() -> impl Parser<'a, ContentType> {
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
    one_of(vec![
        byte_parser(3).then(|_| {
            one_of(vec![
                byte_parser(1), byte_parser(2), byte_parser(3), byte_parser(4),
            ])
                .map(|x| { format!("1.{}", x - 1) })
        }),
        byte_parser(0x7f).then(|_| {
            one_of(vec![
                byte_parser(0x17), byte_parser(0x18), byte_parser(0x19),
                byte_parser(0x1a), byte_parser(0x1b), byte_parser(0x1c),
            ])
                .map(|x| { format!("1.3 (draft {})", x) })
        }),
    ])
}

#[derive(Debug, PartialEq)]
pub enum Extension {
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
    SupportedVersions(Vec<Version>),
    PskExchangeModes,
    KeyShare,
    RenegotiationInfo,
}

fn extension_parser<'a>(client_hello: bool) -> impl Parser<'a, Extension> {
    one_of(vec![
        byte_parser(0).and(byte_parser(0x2b))
            .and(size_header_parser(2, false))
            .skip(1 * client_hello as usize)
            .then(move |((_, _), size)| {
                version_parser().repeat(..=size)
                    .map(move |versions| Extension::SupportedVersions(versions))
                    .skip_to(size - client_hello as usize)
            }),
        one_of(vec![
            byte_parser(0).and(byte_parser(0)).map(|_| { Extension::ServerName }),
            byte_parser(0).and(byte_parser(1)).map(|_| { Extension::MaxFragmentLength }),
            byte_parser(0).and(byte_parser(2)).map(|_| { Extension::ClientCertificate }),
            byte_parser(0).and(byte_parser(3)).map(|_| { Extension::TrustedCaKeys }),
            byte_parser(0).and(byte_parser(4)).map(|_| { Extension::TruncatedHMac }),
            byte_parser(0).and(byte_parser(5)).map(|_| { Extension::StatusRequest }),
            byte_parser(0).and(byte_parser(6)).map(|_| { Extension::UserMapping }),
            byte_parser(0).and(byte_parser(7)).map(|_| { Extension::ClientAuthz }),
            byte_parser(0).and(byte_parser(8)).map(|_| { Extension::ServerAuthz }),
            byte_parser(0).and(byte_parser(9)).map(|_| { Extension::CertType }),
            byte_parser(0).and(byte_parser(0xa)).map(|_| { Extension::SupportedGroups }),
            byte_parser(0).and(byte_parser(0xb)).map(|_| { Extension::EcPointFormats }),
            byte_parser(0).and(byte_parser(0xc)).map(|_| { Extension::Srp }),
            byte_parser(0).and(byte_parser(0xd)).map(|_| { Extension::SignatureAlgorithms }),
            byte_parser(0).and(byte_parser(0xe)).map(|_| { Extension::UseSrtp }),
            byte_parser(0).and(byte_parser(0xf)).map(|_| { Extension::Heartbeat }),
            byte_parser(0).and(byte_parser(0x10)).map(|_| { Extension::ApplicationLayerProtocolNegotiation }),
            byte_parser(0).and(byte_parser(0x11)).map(|_| { Extension::StatusRequestV2 }),
            byte_parser(0).and(byte_parser(0x12)).map(|_| { Extension::SignedCertificateTimestamp }),
            byte_parser(0).and(byte_parser(0x13)).map(|_| { Extension::ClientCertificateType }),
            byte_parser(0).and(byte_parser(0x14)).map(|_| { Extension::ServerCertificateType }),
            byte_parser(0).and(byte_parser(0x15)).map(|_| { Extension::Padding }),
            byte_parser(0).and(byte_parser(0x16)).map(|_| { Extension::EncryptThenMac }),
            byte_parser(0).and(byte_parser(0x17)).map(|_| { Extension::ExtendedMasterSecret }),
            byte_parser(0).and(byte_parser(0x18)).map(|_| { Extension::TokenBinding }),
            byte_parser(0).and(byte_parser(0x19)).map(|_| { Extension::CachedInfo }),
            byte_parser(0).and(byte_parser(0x1c)).map(|_| { Extension::RecordSizeLimit }),
            byte_parser(0).and(byte_parser(0x23)).map(|_| { Extension::SessionTicketTLS }),
            byte_parser(0).and(byte_parser(0x2d)).map(|_| { Extension::PskExchangeModes }),
            byte_parser(0).and(byte_parser(0x33)).map(|_| { Extension::KeyShare }),
            byte_parser(0xff).and(byte_parser(1)).map(|_| { Extension::RenegotiationInfo }),
        ])
            .and(size_header_parser(2, true))
            .map(|(extension, _)| extension),
    ])
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
            extension_parser(true).repeat(..=size3)
                .map(move |extensions| {
                    HandshakeProtocol::ClientHello(version.clone(), size1 / 2, size2, extensions)
                })
                .skip_to(size3)
        )
}

fn server_hello_parser<'a, P>(version_parser: impl Fn() -> P) -> impl Parser<'a, HandshakeProtocol<'a>>
    where P: Parser<'a, Version> + 'a {
    version_parser()
        .skip(32)   // random
        .and(size_header_parser(1, true)) // session id
        .skip(3)// cipher suite + compression method
        .and(size_header_parser(2, false))// extensions
        .then(|((version, _), size)|
            extension_parser(false).repeat(..=size)
                .map(move |extensions| { HandshakeProtocol::ServerHello(version.clone(), extensions) })
                .skip_to(size)
        )
}

pub(crate) fn handshake_parser<'a, P1, F1, P2, F2>(size_header_parser: F1, version_parser: F2) -> impl Parser<'a, HandshakeProtocol<'a>>
    where
        P1: Parser<'a, usize> + 'a,
        F1: Fn(usize, bool) -> P1,
        P2: Parser<'a, Version> + 'a,
        F2: Fn() -> P2 + Copy + 'a {
    one_of(vec![
        byte_parser(1)
            .and(size_header_parser(3, false))
            .then(|(_, size)| client_hello_parser().skip_to(size)),
        byte_parser(2)
            .and(size_header_parser(3, false))
            .then(move |(_, size)| server_hello_parser(version_parser).skip_to(size)),
        one_of(vec![
            byte_parser(11).map(|_| { HandshakeProtocol::Certificate }),
            byte_parser(12).map(|_| { HandshakeProtocol::ServerKeyExchange }),
            byte_parser(14).map(|_| { HandshakeProtocol::ServerHelloDone }),
            byte_parser(16).map(|_| { HandshakeProtocol::ClientKeyExchange }),
        ])
            .and(size_header_parser(3, true))
            .map(|(handshake, _)| { handshake }),
    ])
}

#[derive(Debug, PartialEq)]
pub enum Data<'a> {
    HandshakeProtocol(HandshakeProtocol<'a>),
    ChangeCipherSpec,
    Encrypted(&'a [u8]),
}

pub(crate) fn data_parser<'a, P>(content_type: ContentType, handshake_parser: impl Fn() -> P) -> impl Parser<'a, Data<'a>>
    where P: Parser<'a, HandshakeProtocol<'a>> + 'a {
    move |input: &'a [u8]| {
        match content_type {
            ContentType::ChangeCipherSpec =>
                byte_parser(1)
                    .map(|_| { Data::ChangeCipherSpec })
                    .parse(&input),
            ContentType::Handshake =>
                handshake_parser()
                    .map(|handshake| { Data::HandshakeProtocol(handshake) })
                    .parse(&input)
                    .or_else(|_| {
                        Ok(ParserResult {
                            parsed: Data::HandshakeProtocol(HandshakeProtocol::Encrypted(&input)),
                            remaining: &input[input.len()..],
                        })
                    }),
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
    pub version: Version,
    pub data: Data<'a>,
}

fn tls_handshake_parser<'a>() -> impl Parser<'a, HandshakeProtocol<'a>> {
    handshake_parser(size_header_parser, version_parser)
}

pub fn record_parser<'a>() -> impl Parser<'a, Record<'a>> {
    content_type_parser()
        .and(version_parser())
        .and(size_header_parser(2, false))
        .then(|((content_type, version), size)| {
            data_parser(content_type, tls_handshake_parser)
                .map(move |data| { Record { content_type, version: version.clone(), data } })
                .skip_to(size)
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::general::size_header_parser;
    use crate::parser::Parser;
    use crate::tls;
    use crate::tls::tls_handshake_parser;

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
    fn version_parser_on_input_with_unknown_value_return_error() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 7];
        let result = tls::version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_known_value_return_version() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls::version_parser().parse(&input)?;
        assert_eq!("1.2", result.parsed);
        assert_eq!([7], result.remaining);
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_known_draft_value_return_version() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0x7f, 0x1c, 7];
        let result = tls::version_parser().parse(&input)?;
        assert_eq!("1.3 (draft 28)", result.parsed);
        assert_eq!([7], result.remaining);
        Ok(())
    }

    #[test]
    fn extension_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 8, 3];
        let result = tls::extension_parser(false).parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn extension_parser_on_input_with_known_value_return_extension() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [0, 8, 0, 1, 1, 2, 3];
        let result = tls::extension_parser(false).parse(&input)?;
        assert_eq!(tls::Extension::ServerAuthz, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn extension_parser_on_client_supported_versions_input_return_extension() -> Result<(), Box<dyn Error>> {
        let input: [u8; 8] = [0, 0x2b, 0, 3, 2, 3, 4, 5];
        let result = tls::extension_parser(true).parse(&input)?;
        assert_eq!(tls::Extension::SupportedVersions(vec!["1.3".to_string()]), result.parsed);
        assert_eq!([5], result.remaining);
        Ok(())
    }

    #[test]
    fn extension_parser_on_server_supported_versions_input_return_extension() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [0, 0x2b, 0, 2, 3, 4, 5];
        let result = tls::extension_parser(false).parse(&input)?;
        assert_eq!(tls::Extension::SupportedVersions(vec!["1.3".to_string()]), result.parsed);
        assert_eq!([5], result.remaining);
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
            vec![tls::Extension::ServerName],
        ), result.parsed);
        assert_eq!([0; 2], result.remaining);
        Ok(())
    }

    #[test]
    fn server_hello_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let mut input = [0; 40];
        input[0] = 3;
        input[1] = 3;
        input[39] = 3;
        let result = tls::server_hello_parser(tls::version_parser).parse(&input);
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
        let result = tls::server_hello_parser(tls::version_parser).parse(&input)?;
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
        let result = tls::server_hello_parser(tls::version_parser).parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ServerHello(
            "1.2".to_string(),
            vec![tls::Extension::ExtendedMasterSecret],
        ), result.parsed);
        assert_eq!([0; 2], result.remaining);
        Ok(())
    }

    #[test]
    fn handshake_parser_on_not_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::handshake_parser(size_header_parser, tls::version_parser).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_unknown_type_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 4] = [88, 1, 3, 4];
        let result = tls::handshake_parser(size_header_parser, tls::version_parser).parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_known_type_return_specific_handshake() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [12, 0, 0, 1, 1, 3, 4];
        let result = tls::handshake_parser(size_header_parser, tls::version_parser).parse(&input)?;
        assert_eq!(tls::HandshakeProtocol::ServerKeyExchange, result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_encrypted_content_type_return_data_with_all_input() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls::data_parser(tls::ContentType::Heartbeat, tls_handshake_parser).parse(&input)?;
        assert_eq!(tls::Data::Encrypted(&input), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec, tls_handshake_parser).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec, tls_handshake_parser).parse(b"a");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls::data_parser(tls::ContentType::ChangeCipherSpec, tls_handshake_parser).parse(&input)?;
        assert_eq!(tls::Data::ChangeCipherSpec, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_unknown_input_return_encrypted() -> Result<(), Box<dyn Error>> {
        let input: [u8; 4] = [88, 1, 3, 4];
        let result = tls::data_parser(tls::ContentType::Handshake, tls_handshake_parser).parse(&input)?;
        assert_eq!(tls::Data::HandshakeProtocol(tls::HandshakeProtocol::Encrypted(&[88, 1, 3, 4])), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [16, 0, 0, 1, 1, 2, 3];
        let result = tls::data_parser(tls::ContentType::Handshake, tls_handshake_parser).parse(&input)?;
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