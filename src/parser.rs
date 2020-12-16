#[derive(Debug)]
pub struct ParserResult<'a, T> {
    pub parsed: T,
    pub remaining: &'a [u8],
}

pub trait Parser<'a, T> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String>;
}

impl<'a, F, T> Parser<'a, T> for F where F: Fn(&'a [u8]) -> Result<ParserResult<'a, T>, String> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String> {
        self(input)
    }
}

// fn and<A>(parser1: impl Parser<A>) -> impl Parser<A> {
//     |input| { parser1.parse(input) }
// }

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::*;
    use crate::parser::ParserResult;

    fn bytes_parser<'a>(b: u8) -> impl Parser<'a, u8> {
        move |input: &'a [u8]| {
            if input.is_empty() || input[0] != b {
                return Err(format!("expected {}, got {:?}", b, input));
            }
            Ok(ParserResult { parsed: b, remaining: &input[1..] })
        }
    }

    #[test]
    fn parser_success() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'$').parse(b"$hello")?;
        assert_eq!(b'$', result.parsed);
        assert_eq!(b"hello", result.remaining);
        Ok(())
    }

    #[test]
    fn parser_failure() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'h').parse(b"$hello");
        assert!(result.is_err());
        Ok(())
    }

    // #[test]
    // fn parser_add_operator() -> Result<(), Box<dyn Error>> {
    //     let parser = and(ByteParser { b: b'a' }, ByteParser { b: b'b' });
    //     Ok(())
    // }
}
