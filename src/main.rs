use parser::Parser;
use tls::tls_record_parser;

mod parser;
mod tls;
mod network;

fn main() {
    let payload = "1603030025100000212043dcf44cc39c33ce2cda1a1a5106f249506d7519cdd1cb88b15f3594ca78277a14030300010116030300208e6041083b89ff49d068ec2f735d9dd8da0e286b5f9b84b135be0e4cf538c409";
    let payload = hex::decode(payload).expect("failed to decode payload");

    let mut input = payload.as_slice();
    let mut records = vec![];
    let parser = tls_record_parser();
    while let Ok(result) = parser.parse(input) {
        records.push(result.parsed);
        input = result.remaining;
    }
    println!("{:?}", records);
}
