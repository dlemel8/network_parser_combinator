use crate::parser::{one_of, Parser};

pub mod parser;
pub mod tls;
pub mod general;
pub mod dtls;

#[derive(Debug, PartialEq)]
pub enum Protocol<'a> {
    Dtls(Vec<dtls::Record<'a>>),
    Tls(Vec<tls::Record<'a>>),
    Unknown,
}

pub fn parse(input: &[u8]) -> Protocol {
    let parsed = one_of(vec![
        dtls::record_parser().
            repeat(1..).
            map(|records| Protocol::Dtls(records)),
        tls::record_parser().
            repeat(1..).
            map(|records| Protocol::Tls(records)),
    ])
        .parse(&input);

    match parsed {
        Ok(protocol_result) => protocol_result.parsed,
        Err(_) => Protocol::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::{dtls, parse, Protocol, tls};

    #[test]
    fn parse_on_invalid_input_return_unknown_protocol() -> Result<(), Box<dyn Error>> {
        let input: [u8; 4] = [20, 0xfe, 0xfd, 0];
        let result = parse(&input);
        assert_eq!(Protocol::Unknown, result);
        Ok(())
    }

    #[test]
    fn parse_on_valid_dtls_change_cipher_spec_input_return_dtls_protocol() -> Result<(), Box<dyn Error>> {
        let input: [u8; 17] = [20, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 5, 14, 2];
        let result = parse(&input);
        let expected = Protocol::Dtls(vec![
            dtls::Record {
                content_type: tls::ContentType::ChangeCipherSpec,
                version: "1.2".to_string(),
                data: tls::Data::ChangeCipherSpec,
            }]);
        assert_eq!(expected, result);
        Ok(())
    }

    #[test]
    fn parse_on_valid_tls_application_input_return_tls_protocol() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [23, 3, 2, 0, 2, 100, 5, 14, 2];
        let result = parse(&input);
        let expected = Protocol::Tls(vec![tls::Record {
            content_type: tls::ContentType::ApplicationData,
            version: "1.1".to_string(),
            data: tls::Data::Encrypted(&[100, 5]),
        }]);
        assert_eq!(expected, result);
        Ok(())
    }
}