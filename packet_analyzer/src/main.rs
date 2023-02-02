#![allow(dead_code)]
#![allow(unused_must_use)]

use std::{env, fmt};
use std::fs::File;
use std::io::{Read, Write};
use bitreader::BitReader;

enum IPProtocol {
    ICMP,
    TCP,
    UDP,
    Default,
}

impl fmt::Display for IPProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPProtocol::ICMP => { write!(f, "1 (ICMP)") }
            IPProtocol::TCP => { write!(f, "6 (TCP)") }
            IPProtocol::UDP => { write!(f, "17 (UDP)") }
            IPProtocol::Default => { write!(f, "00 (Default)") }
        }
    }
}


enum ProtocolDatagram {
    TCP(TCPPacket),
    UDP(UDPPacket),
    ICMP(ICMPPacket),
    Placeholder(String),
}

impl ProtocolDatagram {
    fn new() -> ProtocolDatagram {
        ProtocolDatagram::Placeholder("This is the default value".parse().unwrap())
    }
}

impl fmt::Display for ProtocolDatagram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolDatagram::TCP(t) => write!(f, "{}", t),
            ProtocolDatagram::UDP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::ICMP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::Placeholder(_) => write!(f, "This is a placeholder")
        }
    }
}


struct ICMPPacket {
    packet_type: u8,
    code: u8,
    checksum: [u8; 2],
    identifier_be: [u8; 2],
    identifier_le: [u8; 2],
    sequence_be: [u8; 2],
    sequence_le: [u8; 2],
    timestamp: [u8; 8],
    data: Vec<u8>,
}

impl ICMPPacket {
    fn new() -> ICMPPacket {
        ICMPPacket {
            packet_type: 0,
            code: 0,
            checksum: [0, 0],
            identifier_be: [0, 0],
            identifier_le: [0, 0],
            sequence_be: [0, 0],
            sequence_le: [0, 0],
            timestamp: [0, 0, 0, 0, 0, 0, 0, 0],
            data: vec![],
        }
    }
}

impl fmt::Display for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP: -----ICMP Header-----\n");
        write!(f, "ICMP:\n");
        write!(f, "ICMP: type= {}\n", self.packet_type);
        write!(f, "ICMP: Code= {}\n", self.code);
        write!(f, "ICMP: checksum= 0x{:x}{:x}\n", self.checksum[0], self.checksum[1]);
        write!(f, "ICMP:")
    }
}


struct UDPPacket {
    source_port: [u8; 2],
    destination_port: [u8; 2],
    length: [u8; 2],
    checksum: [u8; 2],
    data: Vec<u8>,
}

impl UDPPacket {
    fn new() -> UDPPacket {
        UDPPacket {
            source_port: [0, 0],
            destination_port: [0, 0],
            length: [0, 0],
            checksum: [0, 0],
            data: vec![],
        }
    }
}

impl fmt::Display for UDPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UDP: -----UDP Header-----\n");
        write!(f, "UDP:\n");
        write!(f, "UDP: Source port      = {}\n", u16::from_be_bytes(self.source_port));
        write!(f, "UDP: Destination port = {}\n", u16::from_be_bytes(self.destination_port));
        write!(f, "UDP: Length           = {}\n", u16::from_be_bytes(self.length));
        write!(f, "UDP: Checksum         = 0x{:x}{:x}\n", self.checksum[0], self.checksum[1]);
        write!(f, "UDP:")
    }
}


struct TCPPacket {
    source_port: [u8; 2],
    destination_port: [u8; 2],
    sequence_number: [u8; 4],
    acknowledgement_number: [u8; 4],
    data_offset: u8,
    flags: u8,
    window: [u8; 2],
    checksum: [u8; 2],
    urgent_pointer: [u8; 2],
}

impl TCPPacket {
    fn new() -> TCPPacket {
        TCPPacket {
            source_port: [0, 0],
            destination_port: [0, 0],
            sequence_number: [0, 0, 0, 0],
            acknowledgement_number: [0, 0, 0, 0],
            data_offset: 0,
            flags: 0,
            window: [0, 0],
            checksum: [0, 0],
            urgent_pointer: [0, 0],
        }
    }
}

impl fmt::Display for TCPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TCP: -----TCP Header-----\n");
        write!(f, "TCP:\n");
        write!(f, "TCP: Source Port       = {}\n", u16::from_be_bytes(self.source_port));
        write!(f, "TCP: Destination Port  = {}\n", u16::from_be_bytes(self.destination_port));
        write!(f, "TCP: Sequence number   = {}\n", u32::from_be_bytes(self.sequence_number));
        write!(f, "TCP: Acknowledgement number = {}\n", u32::from_be_bytes(self.acknowledgement_number));
        write!(f, "TCP: Data offset       = {}\n", self.data_offset);
        write!(f, "TCP: Flags             = {}\n", self.flags);
        write!(f, "TCP: Window            = {}\n", u16::from_be_bytes(self.window));
        write!(f, "TCP: Checksum          = 0x{:x}{:x}\n", self.checksum[0], self.checksum[1]);
        write!(f, "TCP: Urgent pointer    = {}\n", u16::from_be_bytes(self.urgent_pointer))
    }
}


struct IPacket {
    version: IPVersion,
    ihl: u8,
    //header length
    tos: u8,
    precedence: u8,
    normal_delay: u8,
    normal_throughput: u8,
    normal_reliability: u8,
    total_length: [u8; 2],
    identification: [u8; 2],
    reserved_flag: u8,
    do_not_fragment_flag: u8,
    last_fragment_flag: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: IPProtocol,
    header_checksum: [u8; 2],
    source_add: [u8; 4],
    destination_add: [u8; 4],
    options: Option<Vec<u8>>,
    datagram: ProtocolDatagram,
}

impl IPacket {
    fn new() -> IPacket {
        IPacket {
            version: IPVersion::V4,
            ihl: 0,
            tos: 0,
            precedence: 0,
            normal_delay: 0,
            normal_throughput: 0,
            normal_reliability: 0,
            total_length: [0, 0],
            identification: [0, 0],
            reserved_flag: 0,
            do_not_fragment_flag: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: IPProtocol::Default,
            header_checksum: [0, 0],
            source_add: [0, 0, 0, 0],
            destination_add: [0, 0, 0, 0],
            options: None,
            datagram: ProtocolDatagram::Placeholder("placeholder".parse().unwrap()),
            last_fragment_flag: 0,
        }
    }
}

impl fmt::Display for IPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP: -----IP Header-----\n");
        write!(f, "IP:\n");
        write!(f, "IP: Version= {}\n", self.version);
        write!(f, "IP: Header length= {} bytes\n", (self.ihl * 4));
        write!(f, "IP: Type of service = 0x{:x}\n", self.tos);
        write!(f, "IP:     xxx. ....= {}(precedence)\n", self.precedence);
        write!(f, "IP:     ...{} ....= normal delay\n", self.normal_delay);
        write!(f, "IP:     .... {}...= normal throughput\n", self.normal_throughput);
        write!(f, "IP:     .... .{}..= normal reliability\n", self.normal_reliability);
        write!(f, "IP: Total length= {} bytes\n", u16::from_be_bytes(self.total_length));
        write!(f, "IP: Identification= {}\n", u16::from_be_bytes(self.identification));
        write!(f, "IP: Flags: \n");
        write!(f, "IP:     {}... .... = reserved\n", self.reserved_flag);
        write!(f, "IP:     .{}.. .... = do not fragment\n", self.do_not_fragment_flag);
        write!(f, "IP:     ..{}. .... = last fragment\n", self.last_fragment_flag);
        write!(f, "IP: Fragment offset= {} bytes\n", self.fragment_offset);
        write!(f, "IP: Time to live= {} seconds/hops\n", self.ttl);
        write!(f, "IP: Protocol= {}\n", self.protocol);
        write!(f, "IP: Header checksum: 0x{:x}{:x}\n", self.header_checksum[0], self.header_checksum[1]);
        write!(f, "IP: Source address: {}\n", format!("{}.{}.{}.{}", self.source_add[0], self.source_add[1], self.source_add[2], self.source_add[3]));
        write!(f, "IP: Destination address: {}\n", format!("{}.{}.{}.{}", self.destination_add[0], self.destination_add[1], self.destination_add[2], self.destination_add[3]));
        match self.options.clone() {
            None => write!(f, "No options\n"),
            Some(op) => write!(f, "Options: {}\n", op.len())
        };
        write!(f, "{}", self.datagram)
    }
}


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


struct EtherFrame {
    packet_size: u32,
    destination_address: [u8; 6],
    source_address: [u8; 6],
    ether_type: [u8; 2],
    version: IPVersion,
    packet: IPacket,
}

impl EtherFrame {
    fn new() -> EtherFrame {
        EtherFrame {
            packet_size: 0,
            destination_address: [0; 6],
            source_address: [0; 6],
            ether_type: [0; 2],
            version: IPVersion::V4,
            packet: IPacket::new(),
        }
    }
}

impl fmt::Display for EtherFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ETHER: -----Ether Header-----\n");
        write!(f, "ETHER:\n");
        write!(f, "ETHER: Packet size= {} bytes\n", self.packet_size);
        write!(f, "ETHER: Destination= {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.destination_address[0],
               self.destination_address[1], self.destination_address[2], self.destination_address[3],
               self.destination_address[4], self.destination_address[5]);
        write!(f, "ETHER: Source     = {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.source_address[0],
               self.source_address[1], self.source_address[2], self.source_address[3],
               self.source_address[4], self.source_address[5]);
        write!(f, "ETHER: Ethertype  = 0x{:x}{:x}\n", self.ether_type[0], self.ether_type[1]);
        write!(f, "ETHER:")
    }
}


struct PcapHeader {
    magic_number: [u8; 4],
    version_major: [u8; 2],
    version_minor: [u8; 2],
    time_zone: [u8; 4],
    timestamp_accuracy: [u8; 4],
    snap_length: [u8; 4],
    link_layer_type: [u8; 4],
}

impl PcapHeader {
    fn new() -> PcapHeader {
        PcapHeader {
            magic_number: [0; 4],
            version_major: [0; 2],
            version_minor: [0; 2],
            time_zone: [0; 4],
            timestamp_accuracy: [0; 4],
            snap_length: [0; 4],
            link_layer_type: [0; 4],
        }
    }
}


struct PcapBlock {
    timestamp_seconds: [u8; 4],
    timestamp_microseconds: [u8; 4],
    captured_length: [u8; 4],
    original_length: [u8; 4],
    ether_frame: EtherFrame,
}

impl PcapBlock {
    fn new() -> PcapBlock {
        PcapBlock {
            timestamp_seconds: [0, 0, 0, 0],
            timestamp_microseconds: [0, 0, 0, 0],
            captured_length: [0, 0, 0, 0],
            original_length: [0, 0, 0, 0],
            ether_frame: EtherFrame::new(),
        }
    }
}


struct PcapFile {
    header: PcapHeader,
    data: Vec<PcapBlock>,
}

impl PcapFile {
    fn new() -> PcapFile {
        PcapFile {
            header: PcapHeader::new(),
            data: Vec::new(),
        }
    }
    fn new_with_header(header: PcapHeader) -> PcapFile {
        PcapFile {
            header,
            data: Vec::new(),
        }
    }
}


fn main() {

    // let mut file = std::fs::File::open("testfile.txt").unwrap();
    // let mut contents = String::new();
    // file.read_to_string(&mut contents).unwrap();
    // print!("{}", contents);


    let args: Vec<String> = env::args().collect();
    let mut file_name = String::from("testmix.pcap");
    if args.len() > 2{

        file_name = args[2].clone();
    }
    println!("This is the argument: {}", file_name);
    let mut pcap_header: PcapHeader = PcapHeader::new(); //Initializing a Pcap Header Structure
    let mut file: File = File::open(file_name).unwrap();
    let file_size: u64 = file.metadata().unwrap().len();
    let mut byte_count: u64 = 0; //This counter is used to track the bytes reader has read from the file

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


fn create_and_return_ether(data: Vec<u8>) -> EtherFrame {
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

    EtherFrame {
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
