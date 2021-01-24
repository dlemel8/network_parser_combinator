use pcap::Capture;
use network_parser_combinator::parse;
use structopt::StructOpt;

const NETWORK_LAYERS_SIZE: usize = 14 + 20 + 32; // eth + ipv4 + tcp

#[derive(StructOpt)]
struct Cli {
    /// Path to pcap file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,
}

fn main() {
    let args = Cli::from_args();
    let mut cap = Capture::from_file(args.path).unwrap();
    while let Ok(packet) = cap.next() {
        if packet.data.len() < NETWORK_LAYERS_SIZE {
            continue
        }

        let payload = &packet.data[NETWORK_LAYERS_SIZE..];
        println!("{:?} {:?}", packet.header, parse(payload));
    }
}