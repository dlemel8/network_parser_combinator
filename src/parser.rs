use std::ops::{Bound, RangeBounds};

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

    fn repeat(self, times: impl RangeBounds<usize> + 'a) -> BoxedParser<'a, Vec<T>> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(repeat(self, times)) }
    }
}

// allow us to use a closure as parser
impl<'a, F, T: 'a> Parser<'a, T> for F where F: Fn(&'a [u8]) -> Result<ParserResult<'a, T>, String> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String> {
        self(input)
    }
}

// allow us to use a combinator functions as part of Parser trait
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

fn repeat<'a, T: 'a>(p: impl Parser<'a, T>, times: impl RangeBounds<usize> + 'a) -> impl Parser<'a, Vec<T>> {
    move |input: &'a [u8]| {
        let limit = match times.end_bound() {
            Bound::Excluded(&x) => x - 1,
            Bound::Included(&x) => x,
            _ => usize::MAX,
        };

        let mut records = vec![];
        let mut internal_input = input;
        while let Ok(result) = p.parse(internal_input) {
            records.push(result.parsed);
            internal_input = result.remaining;
            if limit == records.len() {
                break;
            }
        }

        match times.start_bound() {
            Bound::Included(&x) if x > records.len() => Err(format!("want at least {}, found {}", x, records.len())),
            _ => Ok(ParserResult { parsed: records, remaining: internal_input })
        }
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

    #[test]
    fn repeat_parser_failure() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').repeat(1..).parse(b"ccc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn repeat_parser_success_empty() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').repeat(..).parse(b"ccc")?;
        let empty: Vec<u8> = vec![];
        assert_eq!(empty, result.parsed);
        assert_eq!(b"ccc", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_success_unlimited() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').repeat(1..).parse(b"aaaccc")?;
        assert_eq!(vec![b'a', b'a', b'a'], result.parsed);
        assert_eq!(b"ccc", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_success_limited() -> Result<(), Box<dyn Error>> {
        let result = bytes_parser(b'a').repeat(..=2).parse(b"aaaccc")?;
        assert_eq!(vec![b'a', b'a'], result.parsed);
        assert_eq!(b"accc", result.remaining);
        Ok(())
    }
}
