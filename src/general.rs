use crate::parser::{Parser, ParserResult};

pub(crate) fn nop_parser<'a>() -> impl Parser<'a, ()> {
    move |input: &'a [u8]| {
        Ok(ParserResult {
            parsed: (),
            remaining: &input,
        })
    }
}

pub(crate) fn byte_parser<'a>(b: u8) -> impl Parser<'a, u8> {
    move |input: &'a [u8]| {
        if input.is_empty() || input[0] != b {
            return Err(format!("expected {}, got {:?}", b, input));
        }
        Ok(ParserResult {
            parsed: b,
            remaining: &input[1..],
        })
    }
}

pub(crate) fn size_header_parser<'a>(
    header_size_in_bytes: usize,
    consume: bool,
) -> impl Parser<'a, usize> {
    move |input: &'a [u8]| {
        if input.len() < header_size_in_bytes {
            return Err(format!("header too small {}", input.len()));
        }

        let size = match header_size_in_bytes {
            1 => input[0] as usize,
            2 => u16::from_be_bytes([input[0], input[1]]) as usize,
            3 => u32::from_be_bytes([0, input[0], input[1], input[2]]) as usize,
            _ => {
                return Err(format!(
                    "header size {} is not supported",
                    header_size_in_bytes
                ))
            }
        };

        let end_offset = size + header_size_in_bytes;
        if input.len() < end_offset {
            return Err(format!("not enough data {}", input.len()));
        }

        let new_input = if consume {
            &input[end_offset..]
        } else {
            &input[header_size_in_bytes..]
        };

        Ok(ParserResult {
            parsed: size,
            remaining: new_input,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::general::{byte_parser, size_header_parser, nop_parser};
    use crate::parser::Parser;

    #[test]
    fn nop_parser_success() -> Result<(), Box<dyn Error>> {
        let result = nop_parser().parse(b"hello")?;
        assert_eq!((), result.parsed);
        assert_eq!(b"hello", result.remaining);
        Ok(())
    }

    #[test]
    fn byte_parser_failure() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'h').parse(b"$hello");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn byte_parser_success() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'$').parse(b"$hello")?;
        assert_eq!(b'$', result.parsed);
        assert_eq!(b"hello", result.remaining);
        Ok(())
    }

    #[test]
    fn size_header_parser_on_not_enough_data_for_header_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [1];
        let result = size_header_parser(2, true).parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn size_header_parser_on_value_smaller_than_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 2, 1];
        let result = size_header_parser(2, true).parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn size_header_parser_on_enough_input_and_consume_return_size() -> Result<(), Box<dyn Error>> {
        let input: [u8; 6] = [0, 2, 1, 2, 3, 4];
        let result = size_header_parser(2, true).parse(&input)?;
        assert_eq!(2, result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }

    #[test]
    fn size_header_parser_on_enough_input_and_not_consume_return_size() -> Result<(), Box<dyn Error>>
    {
        let input: [u8; 6] = [0, 2, 1, 2, 3, 4];
        let result = size_header_parser(2, false).parse(&input)?;
        assert_eq!(2, result.parsed);
        assert_eq!([1, 2, 3, 4], result.remaining);
        Ok(())
    }
}
