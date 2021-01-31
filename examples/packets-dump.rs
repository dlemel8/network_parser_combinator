use std::fmt;
use std::fmt::Formatter;
use std::time::Duration;

use crossbeam_channel::bounded;
use crossbeam_utils::thread::scope;
use pcap::Capture;
use structopt::StructOpt;

use network_parser_combinator::{parse_ethernet_packet, Protocol};

#[derive(StructOpt)]
struct Cli {
    /// Path to pcap file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,
}

#[derive(Debug)]
struct RawPacket {
    count: u32,
    timestamp: i64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ParsedPacket<'a> {
    packet: RawPacket,
    protocol: Protocol<'a>,
}

impl<'a> fmt::Display for ParsedPacket<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.packet.count, self.packet.timestamp, self.protocol
        )
    }
}

fn main() {
    let args = Cli::from_args();
    let (packets_sender, packets_receiver) = bounded::<RawPacket>(1);

    scope(|scope| {
        scope.spawn(move |_| loop {
            let to_parse = match packets_receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(packet_to_parse) => packet_to_parse,
                Err(_) => break,
            };
            let mut parsed = ParsedPacket {
                packet: to_parse,
                protocol: Protocol::Unknown,
            };
            parsed.protocol = parse_ethernet_packet(&parsed.packet.bytes);
            println!("{}", parsed);
        });

        let mut packet_count = 0;
        let mut cap = Capture::from_file(args.path).unwrap();
        while let Ok(packet) = cap.next() {
            packet_count += 1;
            let to_parse = RawPacket {
                count: packet_count,
                timestamp: packet.header.ts.tv_sec,
                bytes: packet.data.to_vec(),
            };
            packets_sender.send(to_parse).unwrap();
        }
    })
    .unwrap();
}
