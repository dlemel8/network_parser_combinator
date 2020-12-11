#[derive(Debug)]
struct ParserResult<'a, T> {
    parsed: T,
    remaining: &'a [u8],
}

trait Parser<T> {
    fn parse<'a>(&self, input: &'a [u8]) -> Result<ParserResult<'a, u8>, String>;
}


fn main() {
    // let result = ByteParser { b: b'$' }.parse(b"$hello").unwrap();
    // assert_eq!(b'$', result.parsed);
    // assert_eq!(b"hello", result.remaining);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[derive(Debug)]
    struct ByteParser {
        b: u8,
    }

    impl Parser<u8> for ByteParser {
        fn parse<'a>(&self, input: &'a [u8]) -> Result<ParserResult<'a, u8>, String> {
            if input.len() == 0 || input[0] != self.b {
                return Err(format!("expected {}, got {:?}", self.b, input));
            }
            Ok(ParserResult { parsed: self.b, remaining: &input[1..] })
        }
    }

    #[test]
    fn parser_success() -> Result<(), Box<dyn Error>> {
        let result = ByteParser { b: b'$' }.parse(b"$hello")?;
        assert_eq!(b'$', result.parsed);
        assert_eq!(b"hello", result.remaining);
        Ok(())
    }

    #[test]
    fn parser_failure() -> Result<(), Box<dyn Error>> {
        let result = ByteParser { b: b'h' }.parse(b"$hello");
        assert!(result.is_err());
        Ok(())
    }
}