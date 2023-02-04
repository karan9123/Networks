#![allow(dead_code)]
#![allow(unused_must_use)]

mod ip_protocol;
mod pcap_file_header;
mod pcap_block;
mod ethernet_frame;
mod internet_packet;
mod pcap_file;

use std::{env, fmt};
use std::fs::File;
use std::io::Read;
use bitreader::BitReader;
use ip_protocol::IPProtocol;
use pcap_file_header::PcapFileHeader;
use ethernet_frame::EthernetFrame;
use pcap_block::PcapBlock;
use internet_packet::{ProtocolDatagram, ICMPPacket, UDPPacket, TCPPacket, IPacket};
// use pcap_file::PcapFile;

#[derive(Copy, Clone)]
enum IPVersion {
    V4,
    V6,
}

impl fmt::Display for IPVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IPVersion::V4 => write!(f, "4"),
            IPVersion::V6 => write!(f, "6")
        }
    }
}


#[derive(Debug)]
enum Filter {
    Host(String),
    Port(String),
    Ip(String),
    Tcp(String),
    Udp(String),
    Icmp(String),
    Net(String),
    Count(i32),
    Default(String),
}

impl Filter {
    fn from_str(str: String, arg: String) -> Filter {
        match &str[..] {
            "host" => { Filter::Host(arg) }
            "port" => { Filter::Port(arg) }
            "ip" => { Filter::Ip(arg) }
            "tcp" => { Filter::Tcp(arg) }
            "udp" => { Filter::Udp(arg) }
            "icmp" => { Filter::Icmp(arg) }
            "net" => { Filter::Net(arg) }
            "-c" => { Filter::Count(arg.parse::<i32>().unwrap()) }
            &_ => { Filter::Default(arg) }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut file_name = String::from("testmix.pcap");
    if args.len() > 1 {
        file_name = args[1].clone();
    }
    let mut filter = Filter::Default("default".to_owned());
    if args.len() > 3 {
        filter = Filter::from_str(args[2].clone(), args[3].clone())
    }
    println!("This is the argument: {:?}", filter);


    let mut pcap_header: PcapFileHeader = PcapFileHeader::new(); //Initializing a Pcap Header Structure
    let mut file: File = File::open(file_name).unwrap(); //reading the file
    let file_size: u64 = file.metadata().unwrap().len(); //File size (bytes)
    let mut byte_count: u64 = 0; //This counter is used to track the bytes reader has read from the file


    //This is PCAP Header
    file.read(&mut pcap_header.magic_number).unwrap();
    file.read(&mut pcap_header.version_major).unwrap();
    file.read(&mut pcap_header.version_minor).unwrap();
    file.read(&mut pcap_header.time_zone).unwrap();
    file.read(&mut pcap_header.timestamp_accuracy).unwrap();
    file.read(&mut pcap_header.snap_length).unwrap();
    file.read(&mut pcap_header.link_layer_type).unwrap();
    byte_count += 24;  //Because the size of PCAP Header is 24 bytes

    // let pcap_file = PcapFile::new_with_header(pcap_header); //Initializing the PCAP file with the header
    let mut packet_count = 0; //Count of network packets in PCAP File

    loop {
        if byte_count + 20 > file_size {
            println!("\n\n\n------------>>>>>>Number of packets in the file: {}", packet_count);
            break;
        }

        packet_count += 1;
        let mut pcap_block = PcapBlock::new(); //Initializing a new PCAP Block

        file.read(&mut pcap_block.timestamp_seconds).unwrap();
        file.read(&mut pcap_block.timestamp_microseconds).unwrap();
        file.read(&mut pcap_block.captured_length).unwrap();
        file.read(&mut pcap_block.original_length).unwrap();

        byte_count += 16;
        byte_count += u32::from_ne_bytes(pcap_block.captured_length.clone()) as u64;

        let mut block_data = vec![0_u8; u32::from_ne_bytes(pcap_block.captured_length) as usize];
        file.read(&mut block_data).unwrap();

        pcap_block.ether_frame = create_and_return_ether(block_data);
        // pcap_file.data.push(pcap_block); //Instead of print, we can use this command to create
        // the complete PCAP file struct with Pcap Blocks
        print_pcap(pcap_block);
    }
}

fn create_and_return_ether(data: Vec<u8>) -> EthernetFrame {
    let packet_size = data.len() as u32;
    let destination_address: [u8; 6] = data[0..6].try_into().unwrap();
    let source_address: [u8; 6] = data[6..12].try_into().unwrap();
    let ether_type: [u8; 2] = data[12..14].try_into().unwrap();


    let temp = [data[14].clone()]; //This let is important
    let mut version_head_len_byte = BitReader::new(&temp);
    let ipv = version_head_len_byte.read_u8(4).unwrap();
    let ihl = version_head_len_byte.read_u8(4).unwrap();

    let temp = [data[15].clone()];
    let mut type_of_service = BitReader::new(&temp);
    let precedence = type_of_service.read_u8(3).unwrap();
    let normal_delay = type_of_service.read_u8(1).unwrap();
    let normal_throughput = type_of_service.read_u8(1).unwrap();
    let normal_reliability = type_of_service.read_u8(1).unwrap();
    let tos = type_of_service.read_u8(2).unwrap();

    let total_length: [u8; 2] = data[16..18].try_into().unwrap();
    let identification: [u8; 2] = data[18..20].try_into().unwrap();

    let temp = [data[20].clone(), data[22].clone()];
    let mut flags = BitReader::new(&temp);
    let reserved_flag = flags.read_u8(1).unwrap();
    let do_not_fragment_flag = flags.read_u8(1).unwrap();
    let last_fragment_flag = flags.read_u8(1).unwrap();
    let fragment_offset = flags.peek_u16(0).unwrap();


    //Here first 3 bits are flags and rest 13 are Fragment offset

    let ttl = data[22];
    let temp = data[23];
    let mut protocol = IPProtocol::Default;
    match temp {
        1 => { protocol = IPProtocol::ICMP }
        6 => { protocol = IPProtocol::TCP }
        17 => { protocol = IPProtocol::UDP }
        _ => {}
    }
    let header_checksum: [u8; 2] = data[24..26].try_into().unwrap();

    let source_add: [u8; 4] = data[26..30].try_into().unwrap();
    let destination_add: [u8; 4] = data[30..34].try_into().unwrap();

    let mut options = None;
    let mut current: usize = 34;
    if ihl > 5 {
        current = (34 + ((ihl * 4) - 20)) as usize;
        options = Some(data[34..(current)].to_vec());
    }


    let mut datagram: ProtocolDatagram = ProtocolDatagram::new();
    match protocol {
        IPProtocol::ICMP => {
            let mut icmp = ICMPPacket::new();
            icmp.packet_type = data[current];
            icmp.code = data[current + 1];
            icmp.checksum = data[current + 2..current + 4].try_into().unwrap();
            icmp.identifier_be = data[(current + 4)..(current + 6)].try_into().unwrap();
            icmp.identifier_le = data[(current + 4)..(current + 6)].try_into().unwrap();
            icmp.sequence_be = data[(current + 6)..(current + 8)].try_into().unwrap();
            icmp.sequence_le = data[(current + 6)..(current + 8)].try_into().unwrap();
            icmp.timestamp = data[(current + 8)..(current + 16)].try_into().unwrap();
            icmp.data = data[(current + 16)..].to_vec();
            datagram = ProtocolDatagram::ICMP(icmp);
        }
        IPProtocol::UDP => {
            let mut udp = UDPPacket::new();
            udp.source_port = data[current..(current + 2)].try_into().unwrap();
            udp.destination_port = data[(current + 2)..(current + 4)].try_into().unwrap();
            udp.length = data[(current + 4)..(current + 6)].try_into().unwrap();
            udp.checksum = data[(current + 6)..(current + 8)].try_into().unwrap();
            udp.data = data[(current + 8)..].to_vec();
            datagram = ProtocolDatagram::UDP(udp);
        }
        IPProtocol::TCP => {
            let mut tcp = TCPPacket::new();
            tcp.source_port = data[current..(current + 2)].try_into().unwrap();
            tcp.destination_port = data[(current + 2)..(current + 4)].try_into().unwrap();
            tcp.sequence_number = data[(current + 4)..(current + 8)].try_into().unwrap();
            tcp.acknowledgement_number = data[(current + 8)..(current + 12)].try_into().unwrap();
            tcp.data_offset = data[current + 12];
            tcp.flags = data[current + 13];
            tcp.window = data[(current + 14)..(current + 16)].try_into().unwrap();
            tcp.checksum = data[(current + 16)..(current + 18)].try_into().unwrap();
            tcp.urgent_pointer = data[(current + 18)..(current + 20)].try_into().unwrap();
            datagram = ProtocolDatagram::TCP(tcp);
        }
        _ => {}
    }


    let version = match ipv {
        4 => { IPVersion::V4 }
        _ => { IPVersion::V6 }
    };

    let packet = IPacket {
        version,
        ihl,
        tos,
        precedence,
        normal_delay,
        normal_throughput,
        normal_reliability,
        total_length,
        identification,
        reserved_flag,
        do_not_fragment_flag,
        last_fragment_flag,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source_add,
        destination_add,
        options,
        datagram,

    };

    EthernetFrame {
        packet_size,
        destination_address,
        source_address,
        ether_type,
        version,
        packet,
    }
}

fn print_pcap(block: PcapBlock) {
    // let mut file = File::create("testfile.txt").unwrap();
    //
    // let bytes = bincode::serialize(&block.ether_frame).unwrap();
    // file.write_all(bytes);

    println!("{}", block.ether_frame);
    println!("{}\n\n", block.ether_frame.packet);
}
