use std::cmp::{max, Ordering, Reverse};
use std::collections::BinaryHeap;
use std::fmt::Formatter;
use std::time::Duration;
use std::{fmt, io};

use crossbeam_channel::{bounded, select};
use crossbeam_utils::thread::scope;
use pcap::Capture;
use structopt::StructOpt;

use network_parser_combinator::parse_ethernet_packet;

#[derive(StructOpt)]
struct Cli {
    /// Path to pcap file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,

    /// Number of worker threads to use
    #[structopt(default_value = "4")]
    threads: usize,

    /// Channel read timeout in ms
    #[structopt(default_value = "100")]
    read_timeout: u64,
}

#[derive(Debug)]
struct RawPacket {
    count: u32,
    timestamp: i64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ParsedPacket {
    count: u32,
    timestamp: i64,
    protocol_dump: String,
}

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.count, self.timestamp, self.protocol_dump
        )
    }
}

impl Ord for ParsedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.count.cmp(&other.count)
    }
}

impl PartialOrd for ParsedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ParsedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count
    }
}

impl Eq for ParsedPacket {}

struct ParsedPacketsPrintBuffer {
    parsed_packets: BinaryHeap<Reverse<ParsedPacket>>,
    max_count_in_heap: u32,
    last_printed_count: u32,
}

impl ParsedPacketsPrintBuffer {
    fn new() -> ParsedPacketsPrintBuffer {
        ParsedPacketsPrintBuffer {
            parsed_packets: BinaryHeap::new(),
            max_count_in_heap: 0,
            last_printed_count: 0,
        }
    }

    fn add<W: io::Write>(&mut self, packet: ParsedPacket, writer: &mut W) {
        self.max_count_in_heap = max(self.max_count_in_heap, packet.count);
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
    let args: Cli = Cli::from_args();
    let (packets_sender, packets_receiver) = bounded::<RawPacket>(4 * args.threads);
    let (parsed_sender, parsed_receiver) = bounded::<ParsedPacket>(4 * args.threads);

    scope(|scope| {
        let workers: Vec<_> = (0..args.threads)
            .map(|_| {
                let read_timeout = args.read_timeout.clone();
                let packets_receiver = packets_receiver.clone();
                let parsed_sender = parsed_sender.clone();
                scope.spawn(move |_| loop {
                    let to_parse = match packets_receiver.recv_timeout(Duration::from_millis(read_timeout)) {
                        Ok(packet_to_parse) => packet_to_parse,
                        Err(_) => break,
                    };
                    let protocol = parse_ethernet_packet(&to_parse.bytes);
                    let parsed = ParsedPacket {
                        count: to_parse.count,
                        timestamp: to_parse.timestamp,
                        protocol_dump: format!("{:?}", protocol),
                    };
                    parsed_sender.send(parsed).unwrap();
                })
            })
            .collect();

        let mut packet_count = 0;
        let mut buffer = ParsedPacketsPrintBuffer::new();
        let mut cap = Capture::from_file(args.path).unwrap();
        while let Ok(packet) = cap.next() {
            packet_count += 1;
            let to_parse = RawPacket {
                count: packet_count,
                timestamp: packet.header.ts.tv_sec,
                bytes: packet.data.to_vec(),
            };

            loop {
                select! {
                    send(packets_sender, to_parse) -> _ => {break}
                    recv(parsed_receiver) -> parsed => {buffer.add(parsed.unwrap(), &mut io::stdout())}
                }
            }
        }

        while buffer.last_printed_count < packet_count {
            let parsed = parsed_receiver.recv().unwrap();
            buffer.add(parsed, &mut io::stdout());
        }

        for worker in workers {
            worker.join().unwrap()
        }
    })
        .unwrap();
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use network_parser_combinator::Protocol;

    use crate::{ParsedPacket, ParsedPacketsPrintBuffer};

    #[test]
    fn print_buffer_add_on_packet_with_non_sequential_count_save_in_buffer(
    ) -> Result<(), Box<dyn Error>> {
        let packet = ParsedPacket {
            count: 7,
            timestamp: 0,
            protocol_dump: format!("{:?}", Protocol::Unknown),
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
            count: 1,
            timestamp: 0,
            protocol_dump: format!("{:?}", Protocol::Unknown),
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
            count: 2,
            timestamp: 8,
            protocol_dump: format!("{:?}", Protocol::Unknown),
        };
        let packet2 = ParsedPacket {
            count: 1,
            timestamp: 0,
            protocol_dump: format!("{:?}", Protocol::Unknown),
        };
        let mut buffer = ParsedPacketsPrintBuffer::new();
        let mut stdout = Vec::new();

        buffer.add(packet1, &mut stdout);
        buffer.add(packet2, &mut stdout);

        assert!(buffer.parsed_packets.is_empty());
        assert_eq!(2, buffer.last_printed_count);
        assert_eq!(0, buffer.max_count_in_heap);
        assert_eq!(
            std::str::from_utf8(stdout.as_slice()).unwrap(),
            "1 0 Unknown\n2 8 Unknown\n"
        );
        Ok(())
    }

    #[test]
    fn print_buffer_add_on_non_empty_buffer_and_packet_complete_missing_count_flush_and_print(
    ) -> Result<(), Box<dyn Error>> {
        let packet1 = ParsedPacket {
            count: 8,
            timestamp: 15,
            protocol_dump: format!("{:?}", Protocol::Unknown),
        };
        let packet2 = ParsedPacket {
            count: 6,
            timestamp: 9,
            protocol_dump: format!("{:?}", Protocol::Unknown),
        };
        let packet3 = ParsedPacket {
            count: 7,
            timestamp: 11,
            protocol_dump: format!("{:?}", Protocol::Unknown),
        };
        let mut buffer = ParsedPacketsPrintBuffer::new();
        buffer.last_printed_count = 5;
        let mut stdout = Vec::new();

        buffer.add(packet1, &mut stdout);
        buffer.add(packet2, &mut stdout);
        buffer.add(packet3, &mut stdout);

        assert!(buffer.parsed_packets.is_empty());
        assert_eq!(8, buffer.last_printed_count);
        assert_eq!(0, buffer.max_count_in_heap);
        assert_eq!(
            std::str::from_utf8(stdout.as_slice()).unwrap(),
            "6 9 Unknown\n7 11 Unknown\n8 15 Unknown\n"
        );
        Ok(())
    }
}
