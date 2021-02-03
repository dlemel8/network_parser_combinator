use std::collections::BinaryHeap;
use std::fmt;
use std::fmt::Formatter;
use std::time::Duration;

use crossbeam_channel::bounded;
use crossbeam_utils::thread::scope;
use pcap::Capture;
use structopt::StructOpt;

use network_parser_combinator::{parse_ethernet_packet, Protocol};
use std::cmp::{max, Ordering, Reverse};
use std::io::Write;

#[derive(StructOpt)]
struct Cli {
    /// Path to pcap file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,

    /// Number of worker threads to use
    #[structopt(default_value = "4")]
    threads: usize,
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

impl<'a> Ord for ParsedPacket<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.packet.count.cmp(&other.packet.count)
    }
}

impl<'a> PartialOrd for ParsedPacket<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> PartialEq for ParsedPacket<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.packet.count == other.packet.count
    }
}

impl<'a> Eq for ParsedPacket<'a> {}

struct ParsedPacketsPrintBuffer<'a> {
    parsed_packets: BinaryHeap<Reverse<ParsedPacket<'a>>>,
    max_count_in_heap: u32,
    last_printed_count: u32,
}

impl<'a> ParsedPacketsPrintBuffer<'a> {
    fn new() -> ParsedPacketsPrintBuffer<'a> {
        ParsedPacketsPrintBuffer {
            parsed_packets: BinaryHeap::new(),
            max_count_in_heap: 0,
            last_printed_count: 0,
        }
    }

    fn add<W: Write>(&mut self, packet: ParsedPacket<'a>, writer: &mut W) {
        self.max_count_in_heap = max(self.max_count_in_heap, packet.packet.count);
        self.parsed_packets.push(Reverse(packet));
        let heap_size = self.parsed_packets.len() as u32;

        if self.max_count_in_heap - self.last_printed_count == heap_size {
            self.last_printed_count += heap_size;
            self.max_count_in_heap = 0;
            while let Some(p) = self.parsed_packets.pop() {
                writeln!(writer, "{}", p.0).unwrap();
            }
        }
    }
}

fn main() {
    let args = Cli::from_args();
    let (packets_sender, packets_receiver) = bounded::<RawPacket>(4 * args.threads);

    scope(|scope| {
        let workers: Vec<_> = (0..args.threads)
            .map(|_| {
                scope.spawn(|_| loop {
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
                })
            })
            .collect();

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

        for worker in workers {
            worker.join().unwrap()
        }
    })
    .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::{ParsedPacket, ParsedPacketsPrintBuffer, RawPacket};
    use network_parser_combinator::Protocol;
    use std::error::Error;

    #[test]
    fn print_buffer_add_on_packet_with_non_sequential_count_save_in_buffer(
    ) -> Result<(), Box<dyn Error>> {
        let packet = ParsedPacket {
            packet: RawPacket {
                count: 7,
                timestamp: 0,
                bytes: vec![],
            },
            protocol: Protocol::Unknown,
        };
        let mut buffer = ParsedPacketsPrintBuffer::new();
        buffer.last_printed_count = 4;
        let mut stdout = Vec::new();

        buffer.add(packet, &mut stdout);

        assert_eq!(1, buffer.parsed_packets.len());
        assert_eq!(7, buffer.max_count_in_heap);
        assert_eq!(4, buffer.last_printed_count);
        assert_eq!(stdout, b"");
        Ok(())
    }

    #[test]
    fn print_buffer_add_on_packet_with_sequential_count_print_in() -> Result<(), Box<dyn Error>> {
        let packet = ParsedPacket {
            packet: RawPacket {
                count: 1,
                timestamp: 0,
                bytes: vec![],
            },
            protocol: Protocol::Unknown,
        };
        let mut buffer = ParsedPacketsPrintBuffer::new();
        let mut stdout = Vec::new();

        buffer.add(packet, &mut stdout);

        assert!(buffer.parsed_packets.is_empty());
        assert_eq!(1, buffer.last_printed_count);
        assert_eq!(
            std::str::from_utf8(stdout.as_slice()).unwrap(),
            "1 0 Unknown\n"
        );
        Ok(())
    }

    #[test]
    fn print_buffer_add_on_non_empty_buffer_and_packet_with_sequential_count_flush_and_print(
    ) -> Result<(), Box<dyn Error>> {
        let packet1 = ParsedPacket {
            packet: RawPacket {
                count: 2,
                timestamp: 8,
                bytes: vec![],
            },
            protocol: Protocol::Unknown,
        };
        let packet2 = ParsedPacket {
            packet: RawPacket {
                count: 1,
                timestamp: 0,
                bytes: vec![],
            },
            protocol: Protocol::Unknown,
        };
        let mut buffer = ParsedPacketsPrintBuffer::new();
        let mut stdout = Vec::new();

        buffer.add(packet1, &mut stdout);
        buffer.add(packet2, &mut stdout);

        assert!(buffer.parsed_packets.is_empty());
        assert_eq!(2, buffer.last_printed_count);
        assert_eq!(
            std::str::from_utf8(stdout.as_slice()).unwrap(),
            "1 0 Unknown\n2 8 Unknown\n"
        );
        Ok(())
    }
}
