use crate::general::{byte_parser, sized_by_header_parser};
use crate::parser::{Parser, ParserResult};

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
        if input.is_empty() {
            return Err("nothing to parse".to_string());
        }

        let content_type = match input[0] {
            20 => TlsContentType::ChangeCipherSpec,
            21 => TlsContentType::Alert,
            22 => TlsContentType::Handshake,
            23 => TlsContentType::ApplicationData,
            24 => TlsContentType::Heartbeat,
            _ => return Err(format!("unknown content type {}", input[0])),
        };

        Ok(ParserResult { parsed: content_type, remaining: &input[1..] })
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
pub enum TlsData<'a> {
    HandshakeProtocol,
    ChangeCipherSpec,
    Encrypted(&'a [u8]),
}

fn tls_data_parser<'a>(content_type: TlsContentType) -> impl Parser<'a, TlsData<'a>> {
    move |input: &'a [u8]| {
        match content_type {
            TlsContentType::ChangeCipherSpec =>
                byte_parser(1).parse(&input).map(|ParserResult { parsed: _, remaining }| {
                    ParserResult { parsed: TlsData::ChangeCipherSpec, remaining }
                }),
            _ => Ok(ParserResult { parsed: TlsData::Encrypted(&input), remaining: &input[input.len()..] })
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
            .and(sized_by_header_parser())
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
    use crate::tls::{tls_content_type_parser, tls_data_parser, tls_record_parser, tls_version_parser, TlsContentType, TlsData, TlsRecord};

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