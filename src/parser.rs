use std::ops::{Bound, RangeBounds};

#[derive(Debug)]
pub struct ParserResult<'a, T> {
    pub parsed: T,
    pub remaining: &'a [u8],
}

pub trait Parser<'a, T: 'a> {
    fn parse(&self, input: &'a [u8]) -> Result<ParserResult<'a, T>, String>;

    fn map<U: 'a>(self, f: impl Fn(T) -> U + 'a) -> BoxedParser<'a, U> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(map(self, f)) }
    }

    fn then<U: 'a, P: Parser<'a, U> + 'a>(self, f: impl Fn(T) -> P + 'a) -> BoxedParser<'a, U> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(then(self, f)) }
    }

    fn and<U: 'a>(self, another: impl Parser<'a, U> + 'a) -> BoxedParser<'a, (T, U)> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(and(self, another)) }
    }

    fn skip(self, size: usize) -> BoxedParser<'a, T> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(skip(self, size)) }
    }

    fn skip_to(self, offset: usize) -> BoxedParser<'a, T> where Self: Sized + 'a {
        BoxedParser { parser: Box::new(skip_to(self, offset)) }
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

pub(crate) fn one_of<'a, T: 'a>(options: Vec<impl Parser<'a, T>>) -> impl Parser<'a, T> {
    move |input: &'a [u8]| {
        let internal_input = input;
        for option in options.iter() {
            let result = option.parse(internal_input);
            if result.is_ok() {
                return result;
            }
        };
        Err(format!("all {} options failed", options.len()))
    }
}

fn map<'a, A: 'a, B: 'a>(p: impl Parser<'a, A>, f: impl Fn(A) -> B) -> impl Parser<'a, B> {
    move |input: &'a [u8]| {
        p.parse(&input).map(|ParserResult { parsed: a, remaining }| {
            ParserResult { parsed: f(a), remaining }
        })
    }
}

fn then<'a, A: 'a, B: 'a, P: Parser<'a, B>>(p: impl Parser<'a, A>, f: impl Fn(A) -> P) -> impl Parser<'a, B> {
    move |input: &'a [u8]| {
        p.parse(&input).and_then(|ParserResult { parsed: a, remaining }| {
            f(a).parse(remaining)
        })
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

fn skip<'a, T: 'a>(p: impl Parser<'a, T>, size: usize) -> impl Parser<'a, T> {
    move |input: &'a [u8]| {
        p.parse(&input).and_then(|ParserResult { parsed: a, remaining }| {
            if remaining.len() < size {
                return Err(format!("not enough data {}", remaining.len()));
            }

            Ok(ParserResult { parsed: a, remaining: &remaining[size..] })
        })
    }
}

fn skip_to<'a, T: 'a>(p: impl Parser<'a, T>, offset: usize) -> impl Parser<'a, T> {
    move |input: &'a [u8]| {
        if input.len() < offset {
            return Err(format!("not enough data {}", input.len()));
        }

        p.parse(&input[..offset]).and_then(|ParserResult { parsed: a, remaining: _ }| {
            Ok(ParserResult { parsed: a, remaining: &input[offset..] })
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

        let mut results = vec![];
        let mut internal_input = input;
        while let Ok(result) = p.parse(internal_input) {
            results.push(result.parsed);
            internal_input = result.remaining;
            if limit == results.len() {
                break;
            }
        }

        match times.start_bound() {
            Bound::Included(&x) if x > results.len() => Err(format!("want at least {}, found {}", x, results.len())),
            _ => Ok(ParserResult { parsed: results, remaining: internal_input })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::general::byte_parser;
    use crate::parser::{one_of, Parser};

    #[test]
    fn and_parser_failure_in_first() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').and(byte_parser(b'b')).parse(b"ccc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_failure_in_second() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').and(byte_parser(b'b')).parse(b"acc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn and_parser_success_single() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').and(byte_parser(b'b')).parse(b"abc")?;
        assert_eq!((b'a', b'b'), result.parsed);
        assert_eq!(b"c", result.remaining);
        Ok(())
    }

    #[test]
    fn and_parser_success_multiple() -> Result<(), Box<dyn Error>> {
        let result =
            byte_parser(b'a')
                .and(byte_parser(b'b'))
                .and(byte_parser(b'c'))
                .parse(b"abc")?;
        assert_eq!(((b'a', b'b'), b'c'), result.parsed);
        assert_eq!(b"", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_failure() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(1..).parse(b"ccc");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn repeat_parser_success_empty() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(..).parse(b"ccc")?;
        let empty: Vec<u8> = vec![];
        assert_eq!(empty, result.parsed);
        assert_eq!(b"ccc", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_success_unlimited() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(1..).parse(b"aaaccc")?;
        assert_eq!(vec![b'a', b'a', b'a'], result.parsed);
        assert_eq!(b"ccc", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_success_limited_included() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(..=2).parse(b"aaaccc")?;
        assert_eq!(vec![b'a', b'a'], result.parsed);
        assert_eq!(b"accc", result.remaining);
        Ok(())
    }

    #[test]
    fn repeat_parser_success_limited_excluded() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(..2).parse(b"aaaccc")?;
        assert_eq!(vec![b'a'], result.parsed);
        assert_eq!(b"aaccc", result.remaining);
        Ok(())
    }

    #[test]
    fn one_of_parser_failed() -> Result<(), Box<dyn Error>> {
        let options = vec![byte_parser(b'a'), byte_parser(b'b')];
        let result = one_of(options).parse(b"c");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn one_of_parser_success() -> Result<(), Box<dyn Error>> {
        let options = vec![byte_parser(b'a'), byte_parser(b'b')];
        let result = one_of(options).parse(b"ba")?;
        assert_eq!(b'b', result.parsed);
        assert_eq!(b"a", result.remaining);
        Ok(())
    }

    #[test]
    fn map_parser() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').map(|x| { x - 32 }).parse(b"abc")?;
        assert_eq!(b'A', result.parsed);
        assert_eq!(b"bc", result.remaining);
        Ok(())
    }

    #[test]
    fn then_parser_failed() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').then(|_|byte_parser(b'b')).parse(b"aac");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn then_parser_success() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').then(|_|byte_parser(b'b')).parse(b"abc")?;
        assert_eq!(b'b', result.parsed);
        assert_eq!(b"c", result.remaining);
        Ok(())
    }

    #[test]
    fn skip_to_parser_failed_no_enough_input() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').skip_to(8).parse(b"aaa");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn skip_to_parser_failed_base_parser_try_to_access_after_offser_input() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(2..3).skip_to(1).parse(b"aaa");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn skip_to_parser_success() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').repeat(2..3).skip_to(2).parse(b"aaa")?;
        assert_eq!(vec![b'a', b'a'], result.parsed);
        assert_eq!(b"a", result.remaining);
        Ok(())
    }

    #[test]
    fn skip_parser_failed_no_enough_input() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').skip(4).parse(b"abcd");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn skip_parser_success() -> Result<(), Box<dyn Error>> {
        let result = byte_parser(b'a').skip(3).parse(b"abcd")?;
        assert_eq!(b'a', result.parsed);
        assert!(result.remaining.is_empty());
        Ok(())
    }
}
