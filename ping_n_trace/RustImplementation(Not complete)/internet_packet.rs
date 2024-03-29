use std::fmt;
use num_integer::div_ceil;
use crate::{ICMPPacket, IPProtocol, UdpPacket};

#[repr(C, packed)]
pub(crate) struct IPV4 {
    pub(crate) version_header_len: u8,
    pub(crate) dscp_ecn: u8,
    pub(crate) total_length: [u8; 2],
    pub(crate) identification: [u8; 2],
    pub(crate) flags_fragment_offset: [u8; 2],
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) header_checksum: [u8; 2],
    pub(crate) source_add: [u8; 4],
    pub(crate) destination_add: [u8; 4],
    pub(crate) options: Option<Vec<u8>>,
    pub(crate) datagram: Vec<u8>,
}

impl IPV4 {
    pub(crate) fn new_v4(datagram: Vec<u8>, protocol: u8,
                         ttl: u8, options: Option<Vec<u8>>) -> IPV4 {

        let mut version_header_len = 0x45;
        if options.is_some() {
            let len = options.as_ref().unwrap().len();

            let k = div_ceil(len, 4);
            if k <= 4 {
                version_header_len = 45 + k as u8;
            }
        }
        let total_length = datagram.len();
        let total_length = [(total_length & 0xff) as u8,
            ((total_length >> 8) & 0xff) as u8];

        IPV4 {
            version_header_len,
            dscp_ecn: 0,
            total_length,
            identification: [0, 0],
            flags_fragment_offset: [0, 0],
            ttl,
            protocol,
            header_checksum: [0, 0],
            source_add: [0, 0, 0, 0],
            destination_add: [0, 0, 0, 0],
            options,
            datagram,
        }
    }

    pub(crate) fn to_bytes(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.version_header_len);
        result.push(self.dscp_ecn);
        result.append(&mut self.total_length.to_vec());
        result.append(&mut self.identification.to_vec());
        result.append(&mut self.flags_fragment_offset.to_vec());
        result.push(self.ttl);
        result.push(self.protocol);
        result.append(&mut self.header_checksum.to_vec());
        result.append(&mut self.source_add.to_vec());
        result.append(&mut self.destination_add.to_vec());
        if self.options.is_some(){
            let mut p  = self.options.as_ref().unwrap().clone();
            result.append(&mut p );
        }
        result.append(&mut self.datagram);
        return result;
    }


    /*    pub(crate) fn new_with_ttl(datagram: ICMPPacket, ttl: u8,
                                   total_length: [u8; 2], identification: [u8; 2],
                                   source_add: [u8; 4], destination_add: [u8; 4]) -> IPacket {
            IPacket {
                version: IPVersion::V4,
                ihl: 0,
                tos: 0,
                precedence: 0,
                delay: 0,
                throughput: 0,
                reliability: 0,
                total_length,
                identification,
                reserved_flag: 0,
                do_not_fragment_flag: 0,
                last_fragment_flag: 0,
                fragment_offset: 0,
                ttl,
                protocol: IPProtocol::ICMP,
                header_checksum: [0, 0],
                source_add,
                destination_add,
                options: None,
                datagram,
            }
        }*/
}


/*impl fmt::Display for IPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP: -----IP Header-----\n")?;
        write!(f, "IP:\n")?;
        write!(f, "IP: Version         = {}\n", self.version)?;
        write!(f, "IP: Header length   = {} bytes\n", (self.ihl * 4))?;
        write!(f, "IP: Type of service = 0x{:x}\n", self.tos)?;
        write!(f, "IP:     xxx. ....   = {}(precedence)\n", self.precedence)?;
        write!(f, "IP:     ...{} ....  = {} delay \n", self.delay, if self.delay == 0 { "normal" } else { "low" })?;
        write!(f, "IP:     .... {}...  = {} throughput\n", self.throughput, if self.throughput == 0 { "normal" } else { "high" })?;
        write!(f, "IP:     .... .{}..  = {} reliability\n", self.reliability, if self.reliability == 0 { "normal" } else { "high" })?;
        write!(f, "IP: Total length    = {} bytes\n", u16::from_be_bytes(self.total_length))?;
        write!(f, "IP: Identification  = {}\n", u16::from_be_bytes(self.identification))?;
        write!(f, "IP: Flags: \n")?;
        write!(f, "IP:     {}... ....  = {}\n", self.reserved_flag, if self.reserved_flag == 0 { "reserved" } else { "not reserved" })?;
        write!(f, "IP:     .{}.. ....  = {}fragment\n", self.do_not_fragment_flag, if self.do_not_fragment_flag == 1 { "do not " } else { "" })?;
        write!(f, "IP:     ..{}. ....  = last fragment\n", self.last_fragment_flag)?;
        write!(f, "IP: Fragment offset = {} bytes\n", self.fragment_offset)?;
        write!(f, "IP: Time to live    = {} seconds/hops\n", self.ttl)?;
        write!(f, "IP: Protocol        = {}\n", self.protocol)?;
        write!(f, "IP: Header checksum = 0x{:x}{:x}\n", self.header_checksum[0], self.header_checksum[1])?;
        write!(f, "IP: Source address  = {}\n", format!("{}.{}.{}.{}", self.source_add[0], self.source_add[1], self.source_add[2], self.source_add[3]))?;
        write!(f, "IP: Destination address= {}\n", format!("{}.{}.{}.{}", self.destination_add[0], self.destination_add[1], self.destination_add[2], self.destination_add[3]))?;
        match self.options.clone() {
            None => write!(f, "No options\n")?,
            Some(op) => write!(f, "Options: {}\n", op.len())?
        };
        write!(f, "{}", self.datagram)
    }
}*/