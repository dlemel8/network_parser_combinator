use crate::general::{byte_parser, sized_by_header_parser};
use crate::parser::{one_of, Parser, ParserResult};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
}

fn tls_content_type_parser<'a>() -> impl Parser<'a, TlsContentType> {
    move |input: &'a [u8]| {
        one_of(vec![
            byte_parser(20).map(|_| { TlsContentType::ChangeCipherSpec }),
            byte_parser(21).map(|_| { TlsContentType::Alert }),
            byte_parser(22).map(|_| { TlsContentType::Handshake }),
            byte_parser(23).map(|_| { TlsContentType::ApplicationData }),
            byte_parser(24).map(|_| { TlsContentType::Heartbeat }),
        ])
            .parse(&input)
            .or_else(|_| {
                Err(format!("unknown content type {:?}", input))
            })
    }
}

fn tls_version_parser<'a>() -> impl Parser<'a, String> {
    move |input: &'a [u8]| {
        if input.len() < 2 {
            return Err(format!("not enough data {}", input.len()));
        }

        let version = match (input[0], input[1]) {
            (3, y @ 1..=4) => format!("1.{}", y - 1),
            (x, y) => return Err(format!("unknown version {}:{}", x, y)),
        };

        Ok(ParserResult { parsed: version, remaining: &input[2..] })
    }
}

#[derive(Debug, PartialEq)]
pub enum TlsHandshakeProtocol<'a> {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    ServerHelloDone,
    ClientKeyExchange,
    Encrypted(&'a [u8]),
}

fn tls_handshake_parser<'a>() -> impl Parser<'a, TlsHandshakeProtocol<'a>> {
    move |input: &'a [u8]| {
        if input.is_empty() {
            return Err("nothing to parse".to_string());
        }

        one_of(vec![
            byte_parser(1).map(|_| { TlsHandshakeProtocol::ClientHello }),
            byte_parser(2).map(|_| { TlsHandshakeProtocol::ServerHello }),
            byte_parser(11).map(|_| { TlsHandshakeProtocol::Certificate }),
            byte_parser(12).map(|_| { TlsHandshakeProtocol::ServerKeyExchange }),
            byte_parser(14).map(|_| { TlsHandshakeProtocol::ServerHelloDone }),
            byte_parser(16).map(|_| { TlsHandshakeProtocol::ClientKeyExchange }),
        ])
            .and(sized_by_header_parser(3))
            .map(|(handshake_type, _)| { handshake_type })
            .parse(&input)
            .or_else(|_| {
                Ok(ParserResult {
                    parsed: TlsHandshakeProtocol::Encrypted(&input),
                    remaining: &input[input.len()..],
                })
            })
    }
}

#[derive(Debug, PartialEq)]
pub enum TlsData<'a> {
    HandshakeProtocol(TlsHandshakeProtocol<'a>),
    ChangeCipherSpec,
    Encrypted(&'a [u8]),
}

fn tls_data_parser<'a>(content_type: TlsContentType) -> impl Parser<'a, TlsData<'a>> {
    move |input: &'a [u8]| {
        match content_type {
            TlsContentType::ChangeCipherSpec =>
                byte_parser(1)
                    .map(|_| { TlsData::ChangeCipherSpec })
                    .parse(&input),
            TlsContentType::Handshake =>
                tls_handshake_parser()
                    .map(|handshake| { TlsData::HandshakeProtocol(handshake) })
                    .parse(&input),
            _ => Ok(ParserResult {
                parsed: TlsData::Encrypted(&input),
                remaining: &input[input.len()..],
            })
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TlsRecord<'a> {
    pub content_type: TlsContentType,
    pub version: String,
    pub data: TlsData<'a>,
}

pub fn tls_record_parser<'a>() -> impl Parser<'a, TlsRecord<'a>> {
    move |input: &'a [u8]| {
        tls_content_type_parser()
            .and(tls_version_parser())
            .and(sized_by_header_parser(2))
            .parse(&input)
            .and_then(|ParserResult { parsed: ((content_type, version), raw_data), remaining }| {
                tls_data_parser(content_type).parse(raw_data)
                    .map(|ParserResult { parsed: data, remaining: _ }| {
                        ParserResult { parsed: TlsRecord { content_type, version, data }, remaining }
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::parser::Parser;
    use crate::tls::{tls_content_type_parser, tls_data_parser, tls_handshake_parser, tls_record_parser, tls_version_parser, TlsContentType, TlsData, TlsHandshakeProtocol, TlsRecord};

    #[test]
    fn content_type_parser_on_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls_content_type_parser().parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_unknown_value_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls_content_type_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_known_value_return_content_type() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [22, 2, 3];
        let result = tls_content_type_parser().parse(&input)?;
        assert_eq!(TlsContentType::Handshake, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn version_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [1];
        let result = tls_version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_unknown_value_return_version() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 7];
        let result = tls_version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_known_value_return_it() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls_version_parser().parse(&input)?;
        assert_eq!("1.2", result.parsed);
        assert_eq!([7], result.remaining);
        Ok(())
    }

    #[test]
    fn handshake_parser_on_not_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls_handshake_parser().parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_unknown_type_return_encrypted_handshake() -> Result<(), Box<dyn Error>> {
        let input: [u8; 4] = [88, 1, 3, 4];
        let result = tls_handshake_parser().parse(&input)?;
        assert_eq!(TlsHandshakeProtocol::Encrypted(&[88, 1, 3, 4]), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn handshake_parser_on_input_with_known_type_return_specific_handshake() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [1, 0, 0, 1, 1, 3, 4];
        let result = tls_handshake_parser().parse(&input)?;
        assert_eq!(TlsHandshakeProtocol::ClientHello, result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_encrypted_content_type_return_data_with_all_input() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [3, 3, 7];
        let result = tls_data_parser(TlsContentType::Heartbeat).parse(&input)?;
        assert_eq!(TlsData::Encrypted(&input), result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls_data_parser(TlsContentType::ChangeCipherSpec).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls_data_parser(TlsContentType::ChangeCipherSpec).parse(b"a");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_change_cipher_spec_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = tls_data_parser(TlsContentType::ChangeCipherSpec).parse(&input)?;
        assert_eq!(TlsData::ChangeCipherSpec, result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = tls_data_parser(TlsContentType::Handshake).parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn data_parser_on_handshake_content_type_and_valid_input_return_data() -> Result<(), Box<dyn Error>> {
        let input: [u8; 7] = [1, 0, 0, 1, 1, 2, 3];
        let result = tls_data_parser(TlsContentType::Handshake).parse(&input)?;
        assert_eq!(TlsData::HandshakeProtocol(TlsHandshakeProtocol::ClientHello), result.parsed);
        assert_eq!([2, 3], result.remaining);
        Ok(())
    }

    #[test]
    fn record_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 2, 0, 10, 100, 5, 14, 2];
        let result = tls_record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 100, 0, 2, 100, 5, 14, 2];
        let result = tls_record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_valid_application_input_return_record() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 2, 0, 2, 100, 5, 14, 2];
        let result = tls_record_parser().parse(&input)?;
        let expected = TlsRecord {
            content_type: TlsContentType::ApplicationData,
            version: "1.1".to_string(),
            data: TlsData::Encrypted(&[100, 5]),
        };
        assert_eq!(expected, result.parsed);
        assert_eq!([14, 2], result.remaining);
        Ok(())
    }

    #[test]
    fn record_parser_on_valid_change_cipher_spec_input_return_record() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [20, 3, 1, 0, 1, 1, 5, 14, 2];
        let result = tls_record_parser().parse(&input)?;
        let expected = TlsRecord {
            content_type: TlsContentType::ChangeCipherSpec,
            version: "1.0".to_string(),
            data: TlsData::ChangeCipherSpec,
        };
        assert_eq!(expected, result.parsed);
        assert_eq!([5, 14, 2], result.remaining);
        Ok(())
    }
}