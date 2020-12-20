#[derive(Debug)]
pub struct ParserResult<'a, T> {
    pub parsed: T,
    pub remaining: &'a [u8],
}

pub trait Parser<'a, T: 'a> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String>;

    fn and<U: 'a>(self, another: impl Parser<'a, U> + 'a) -> BoxedParser<'a, (T, U)> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(and(self, another)) }
    }
}

// allow us to use closure as parser
impl<'a, F, T: 'a> Parser<'a, T> for F where F: Fn(&'a [u8]) -> Result<ParserResult<'a, T>, String> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String> {
        self(input)
    }
}

// allow us to use
pub struct BoxedParser<'a, T> {
    parser: Box<dyn Parser<'a, T> + 'a>
}

impl<'a, T> Parser<'a, T> for BoxedParser<'a, T> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String> {
        self.parser.parse(input)
    }
}

fn and<'a, A: 'a, B: 'a>(p1: impl Parser<'a, A>, p2: impl Parser<'a, B>) -> impl Parser<'a, (A, B)> {
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
        let result = bytes_parser(b'a').and(bytes_parser(b'b')).parse(b"ccc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_failure_in_second() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').and(bytes_parser(b'b')).parse(b"acc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_success_single() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').and(bytes_parser(b'b')).parse(b"abc")?;
        assert_eq!((b'a', b'b'), result.parsed);
        assert_eq!(b"c", result.remaining);
        Ok(())
    }

    #[test]
    fn and_parser_success_multiple() -> Result<(), Box<dyn Error>> {
        let result =
            bytes_parser(b'a')
                .and(bytes_parser(b'b'))
                .and(bytes_parser(b'c'))
                .parse(b"abc")?;
        assert_eq!(((b'a', b'b'), b'c'), result.parsed);
        assert_eq!(b"", result.remaining);
        Ok(())
    }
}
