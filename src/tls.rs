use crate::parser::{Parser, ParserResult};

#[derive(Debug, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
}

pub struct TlsContentTypeParser {}

impl Parser<TlsContentType> for TlsContentTypeParser {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<ParserResult<'a, TlsContentType>, String> {
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

#[derive(Debug)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version: String,
}

pub struct TlsRecordParser {}

impl Parser<TlsRecord> for TlsRecordParser {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<ParserResult<'a, TlsRecord>, String> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::parser::Parser;
    use crate::tls::{TlsContentType, TlsContentTypeParser};

    #[test]
    fn content_type_parser_on_empty_input_return_err() -> Result<(), Box<dyn Error>> {
        let result = TlsContentTypeParser {}.parse(b"");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_unknown_type_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [1, 2, 3];
        let result = TlsContentTypeParser {}.parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn content_type_parser_on_input_with_known_type_return_content_type() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [22, 2, 3];
        let result = TlsContentTypeParser {}.parse(&input)?;
        assert_eq!(TlsContentType::Handshake, result.parsed);
        assert_eq!(&input[1..], result.remaining);
        Ok(())
    }
}