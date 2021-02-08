# Network Parser Combinator
This repo contains parser combinator framework and use it to partially parse some TLS protocol variants.

## Parser Combinators
A parser is a function that take bytes and return a result.  
Parsers are defined by a trait and implemented by closures.

A combinator is a function that take other parsers and return new parser.  
Combinators are implemented as methods with default implementation on parser trait.

## Network Protocols
Using parsers and combinators, network protocols can be parsed.  
All supported protocols can be parsed via a single library function that take packet(s) payload and return parsed objects.  

Currently, tested protocols are:
* TLS 1.2
* TLS 1.3
* DTLS 1.2

## Examples
There is a single example of multi-threaded executable that dumps packets of a pcap file.  
The main thread is sending packets to parse and receiving parsed packets to worker threads via channels.  
Parsed packets are temporarily stored in a binary heap until they get printed.