use crate::general::{byte_parser, size_header_parser};
use crate::parser::{one_of, Parser};
use crate::tls;

type Version = String;

fn version_parser<'a>() -> impl Parser<'a, Version> {
    byte_parser(0xfe).then(|_| {
        one_of(vec![
            byte_parser(0xff).map(|_| "1.0".to_string()),
            byte_parser(0xfd).map(|_| "1.2".to_string()),
        ])
    })
}

#[derive(Debug, PartialEq)]
pub struct Record<'a> {
    pub content_type: tls::ContentType,
    pub version: Version,
    pub data: tls::Data<'a>,
}

fn handshake_size_header_parser<'a>(header_size_in_bytes: usize, consume: bool) -> impl Parser<'a, usize> {
    size_header_parser(header_size_in_bytes, consume)
        .skip(8)  // message sequence + fragment offset + fragment size
}

fn client_context_parser<'a>() -> impl Parser<'a, ()> {
    size_header_parser(1, true) // session id
        .and(size_header_parser(1, true)) // cookie
        .map(|_| ())
}

fn hello_verify_request_parser<'a>() -> impl Parser<'a, tls::HandshakeProtocol<'a>> {
    byte_parser(3)
        .and(handshake_size_header_parser(3, true))
        .map(|_| { tls::HandshakeProtocol::HelloVerifyRequest })
}

fn dtls_handshake_parser<'a>() -> impl Parser<'a, tls::HandshakeProtocol<'a>> {
    move |input: &'a [u8]| {
        tls::handshake_parser(handshake_size_header_parser, version_parser, client_context_parser)
            .parse(&input)
            .or_else(|_| {
                hello_verify_request_parser()
                    .parse(&input)
            })
    }
}

pub(crate) fn record_parser<'a>() -> impl Parser<'a, Record<'a>> {
    tls::content_type_parser()
        .and(version_parser())
        .skip(8)  // epoch + sequence number
        .and(size_header_parser(2, false))
        .then(|((content_type, version), size)| {
            tls::data_parser(content_type, dtls_handshake_parser)
                .map(move |data| { Record { content_type, version: version.clone(), data } })
                .skip_to(size)
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::{dtls, tls};
    use crate::parser::Parser;

    #[test]
    fn version_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [0xfe];
        let result = dtls::version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_unknown_value_return_error() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0xfe, 0xfe, 7];
        let result = dtls::version_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn version_parser_on_input_with_known_value_return_version() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0xfe, 0xfd, 7];
        let result = dtls::version_parser().parse(&input)?;
        assert_eq!("1.2", result.parsed);
        assert_eq!([7], result.remaining);
        Ok(())
    }

    #[test]
    fn record_parser_on_not_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 9] = [20, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0];
        let result = dtls::record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_invalid_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 17] = [20, 0xfe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 5, 14, 2];
        let result = dtls::record_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn record_parser_on_valid_change_cipher_spec_input_return_record() -> Result<(), Box<dyn Error>> {
        let input: [u8; 17] = [20, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 5, 14, 2];
        let result = dtls::record_parser().parse(&input)?;
        let expected = dtls::Record {
            content_type: tls::ContentType::ChangeCipherSpec,
            version: "1.2".to_string(),
            data: tls::Data::ChangeCipherSpec,
        };
        assert_eq!(expected, result.parsed);
        assert_eq!([5, 14, 2], result.remaining);
        Ok(())
    }
}