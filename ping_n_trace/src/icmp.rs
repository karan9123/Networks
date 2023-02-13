use std::{fmt, mem, slice};


///ICMP Packet struct
#[repr(C, packed)]
pub(crate) struct ICMPPacket {
    pub(crate) packet_type: u8,
    pub(crate) code: u8,
    pub(crate) checksum: u16,
    pub(crate) identifier: u16,
    pub(crate) sequence: u16,
    pub(crate) data: Vec<u8>,
}

impl ICMPPacket {
    pub(crate) fn new_echo_request(data: Vec<u8>, code: u8,
                                   checksum: u16, identifier: u16,
                                   sequence: u16) -> ICMPPacket {
        ICMPPacket {
            packet_type: 8,
            code,
            checksum,
            identifier,
            sequence,
            data,
        }
    }

    pub(crate) fn checksum(&mut self) {
        let mut sum = 0u32;
        let buffer = unsafe {
            slice::from_raw_parts(self as *const ICMPPacket as *const u16,
                                  mem::size_of::<ICMPPacket>() / 2)
        };

        for i in 0..(buffer.len()) {
            sum = sum.wrapping_add(u32::from(buffer[i]));
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum = sum + (sum >> 16);

        self.checksum = !sum as u16;
    }
}

impl fmt::Display for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP: -----ICMP Header-----\n")?;
        write!(f, "ICMP:\n")?;
        write!(f, "ICMP: type= {}\n", self.packet_type)?;
        write!(f, "ICMP: Code= {}\n", self.code)?;
        write!(f, "ICMP: checksum= 0x{:x}\n", self.checksum)?;
        write!(f, "ICMP: identifier= /**/0x{:x}\n", self.identifier)?;
        write!(f, "ICMP: sequence= 0x{:x}\n", self.sequence)?;
        write!(f, "ICMP:")
    }
}


/// ICMP Type enum
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ICMPType {
    EchoRequest = 8,
    EchoReply = 0,
    TimeExceeded = 11,
    DestinationUnreachable = 3,
    Redirect = 5,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeStampRequest = 13,
    TimeStampReply = 14,
}

impl fmt::Display for ICMPType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ICMPType::EchoRequest => write!(f, "Echo Request"),
            ICMPType::EchoReply => write!(f, "Echo Reply"),
            ICMPType::TimeExceeded => write!(f, "Time Exceeded"),
            ICMPType::DestinationUnreachable => write!(f, "Destination Unreachable"),
            ICMPType::Redirect => write!(f, "Redirect"),
            ICMPType::RouterAdvertisement => write!(f, "Router Advertisement"),
            ICMPType::RouterSolicitation => write!(f, "Router Solicitation"),
            ICMPType::TimeStampRequest => write!(f, "Time Stamp Request"),
            ICMPType::TimeStampReply => write!(f, "Time Stamp Reply"),
        }
    }
}