use crate::parser::{Parser, ParserResult};

pub fn byte_parser<'a>(b: u8) -> impl Parser<'a, u8> {
    move |input: &'a [u8]| {
        if input.is_empty() || input[0] != b {
            return Err(format!("expected {}, got {:?}", b, input));
        }
        Ok(ParserResult { parsed: b, remaining: &input[1..] })
    }
}

pub fn sized_by_header_parser<'a>() -> impl Parser<'a, &'a [u8]> {
    move |input: &'a [u8]| {
        if input.len() < 2 {
            return Err(format!("header too small {}", input.len()));
        }

        let size = u16::from_be_bytes([input[0], input[1]]) as usize;
        let end_offset = size + 2;
        if input.len() < end_offset {
            return Err(format!("not enough data {}", input.len()));
        }

        Ok(ParserResult { parsed: &input[2..end_offset], remaining: &input[end_offset..] })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::general::{sized_by_header_parser, byte_parser};
    use crate::parser::Parser;


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
    fn sized_by_header_parser_on_not_enough_data_for_header_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [1];
        let result = sized_by_header_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn sized_by_header_parser_on_value_smaller_than_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 2, 1];
        let result = sized_by_header_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn sized_by_header_parser_on_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 6] = [0, 2, 1, 2, 3, 4];
        let result = sized_by_header_parser().parse(&input)?;
        assert_eq!([1, 2], result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }
}