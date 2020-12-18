use crate::parser::{Parser, ParserResult};

pub fn size_header_parser<'a>() -> impl Parser<'a, &'a [u8]> {
    move |input: &'a [u8]| {
        if input.len() < 2 {
            return Err(format!("header too small {}", input.len()));
        }

        let size = u16::from_be_bytes([input[0], input[1]]) as usize;
        let end_offset = size + 2;
        if input.len() < end_offset {
            return Err(format!("not enough data {}", input.len()));
        }

        Ok(ParserResult{ parsed: &input[2..end_offset], remaining: &input[end_offset..] })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::network::size_header_parser;
    use crate::parser::Parser;

    #[test]
    fn size_header_parser_on_not_enough_data_for_header_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 1] = [1];
        let result = size_header_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn size_header_parser_on_value_smaller_than_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 3] = [0, 2, 1];
        let result = size_header_parser().parse(&input);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn size_header_parser_on_enough_input_return_err() -> Result<(), Box<dyn Error>> {
        let input: [u8; 6] = [0, 2, 1, 2, 3, 4];
        let result = size_header_parser().parse(&input)?;
        assert_eq!([1, 2], result.parsed);
        assert_eq!([3, 4], result.remaining);
        Ok(())
    }
}