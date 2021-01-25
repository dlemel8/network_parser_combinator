use pcap::Capture;
use network_parser_combinator::parse_ethernet_packet;
use structopt::StructOpt;

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
        println!("{:?} {:?}", packet.header, parse_ethernet_packet(packet.data));
    }
}