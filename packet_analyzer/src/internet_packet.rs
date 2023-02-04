use std::fmt;
use crate::{IPProtocol, IPVersion};

pub(crate) enum ProtocolDatagram {
    TCP(TCPPacket),
    UDP(UDPPacket),
    ICMP(ICMPPacket),
    Default(String),
}

impl ProtocolDatagram {
    pub(crate) fn new() -> ProtocolDatagram {
        ProtocolDatagram::Default("This is the default value".parse().unwrap())
    }
}

impl fmt::Display for ProtocolDatagram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolDatagram::TCP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::UDP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::ICMP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::Default(_) => write!(f, "This is a placeholder")
        }
    }
}


pub(crate) struct ICMPPacket {
    pub(crate) packet_type: u8,
    pub(crate) code: u8,
    pub(crate) checksum: [u8; 2],
    pub(crate) identifier_be: [u8; 2],
    pub(crate) identifier_le: [u8; 2],
    pub(crate) sequence_be: [u8; 2],
    pub(crate) sequence_le: [u8; 2],
    pub(crate) timestamp: [u8; 8],
    pub(crate) data: Vec<u8>,
}

impl ICMPPacket {
    pub(crate) fn new() -> ICMPPacket {
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


pub(crate) struct UDPPacket {
    pub(crate) source_port: [u8; 2],
    pub(crate) destination_port: [u8; 2],
    pub(crate) length: [u8; 2],
    pub(crate) checksum: [u8; 2],
    pub(crate) data: Vec<u8>,
}

impl UDPPacket {
    pub(crate) fn new() -> UDPPacket {
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


pub(crate) struct TCPPacket {
    pub(crate) source_port: [u8; 2],
    pub(crate) destination_port: [u8; 2],
    pub(crate) sequence_number: [u8; 4],
    pub(crate) acknowledgement_number: [u8; 4],
    pub(crate) data_offset: u8,
    pub(crate) flags: u8,
    pub(crate) window: [u8; 2],
    pub(crate) checksum: [u8; 2],
    pub(crate) urgent_pointer: [u8; 2],
}

impl TCPPacket {
    pub(crate) fn new() -> TCPPacket {
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


pub(crate) struct IPacket {
    pub(crate) version: IPVersion,
    pub(crate) ihl: u8,
    //pub(crate) header length
    pub(crate) tos: u8,
    pub(crate) precedence: u8,
    pub(crate) normal_delay: u8,
    pub(crate) normal_throughput: u8,
    pub(crate) normal_reliability: u8,
    pub(crate) total_length: [u8; 2],
    pub(crate) identification: [u8; 2],
    pub(crate) reserved_flag: u8,
    pub(crate) do_not_fragment_flag: u8,
    pub(crate) last_fragment_flag: u8,
    pub(crate) fragment_offset: u16,
    pub(crate) ttl: u8,
    pub(crate) protocol: IPProtocol,
    pub(crate) header_checksum: [u8; 2],
    pub(crate) source_add: [u8; 4],
    pub(crate) destination_add: [u8; 4],
    pub(crate) options: Option<Vec<u8>>,
    pub(crate) datagram: ProtocolDatagram,
}

impl IPacket {
    pub(crate) fn new() -> IPacket {
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
            datagram: ProtocolDatagram::Default("placeholder".parse().unwrap()),
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