use std::error::Error;

use parser::Parser;
use tls::tls_record_parser;

mod parser;
mod tls;
mod network;

fn main() -> Result<(), Box<dyn Error>> {
    let payload = "1603030025100000212043dcf44cc39c33ce2cda1a1a5106f249506d7519cdd1cb88b15f3594ca78277a14030300010116030300208e6041083b89ff49d068ec2f735d9dd8da0e286b5f9b84b135be0e4cf538c409";
    let payload = hex::decode(payload).expect("failed to decode payload");
    let parser = tls_record_parser().repeat(0..);
    let records = parser.parse(payload.as_slice())?;
    assert!(records.remaining.is_empty());
    println!("{:?}", records.parsed);
    Ok(())
}
