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

pub fn and<'a, A, B>(p1: impl Parser<'a, A>, p2: impl Parser<'a, B>) -> impl Parser<'a, (A, B)> {
    move |input: &'a [u8]| {
        p1.parse(input).and_then(|ParserResult { parsed: a, remaining: remaining1 }| {
            p2.parse(remaining1).map(|ParserResult { parsed: b, remaining: remaining2 }| {
                ParserResult { parsed: (a, b), remaining: remaining2 }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::*;
    use crate::parser::{ParserResult, and};

    fn bytes_parser<'a>(b: u8) -> impl Parser<'a, u8> {
        move |input: &'a [u8]| {
            if input.is_empty() || input[0] != b {
                return Err(format!("expected {}, got {:?}", b, input));
            }
            Ok(ParserResult { parsed: b, remaining: &input[1..] })
        }
    }

    #[test]
    fn parser_failure() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'h').parse(b"$hello");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn parser_success() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'$').parse(b"$hello")?;
        assert_eq!(b'$', result.parsed);
        assert_eq!(b"hello", result.remaining);
        Ok(())
    }


    #[test]
    fn and_parser_failure_in_first() -> Result<(), Box<dyn Error>> {
        let result = and(bytes_parser(b'a'), bytes_parser(b'b')).parse(b"ccc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_failure_in_second() -> Result<(), Box<dyn Error>> {
        let result = and(bytes_parser(b'a'), bytes_parser(b'b')).parse(b"acc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_success() -> Result<(), Box<dyn Error>> {
        let result = and(bytes_parser(b'a'), bytes_parser(b'b')).parse(b"abc")?;
        assert_eq!((b'a', b'b'), result.parsed);
        assert_eq!(b"c", result.remaining);
        Ok(())
    }
}
