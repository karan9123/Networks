use std::fs;
use std::io::Read;
use nom::{number::complete::be_u16, number::complete::be_u32, IResult, bytes::complete::take};
use if_addrs::{get_if_addrs, IfAddr};
use std::net::Ipv4Addr;
use std::path::Path;
use mac_address::get_mac_address;


#[derive(Debug)]
pub struct ArpPacket {
    /// hardware type
    pub hardware_type: u16,
    /// protocol type
    pub protocol_type: u16,
    /// hardware address length
    pub header_len: u8,
    /// protocol address length
    pub protocol_len: u8,
    /// ARP operation (request or reply)
    pub operation: u16,
    /// sender hardware address (MAC address)
    pub sender_hw_addr: [u8; 6],
    /// sender protocol address (IPv4 address)
    pub sender_proto_addr: [u8; 4],
    /// target hardware address (MAC address)
    pub target_hw_addr: [u8; 6],
    /// target protocol address (IPv4 address)
    pub target_proto_addr: [u8; 4],

}

fn get_my_ipv4_protocol_address() -> Option<Ipv4Addr> {
    // Get all of the network interfaces on the system
    let if_addrs = match get_if_addrs() {
        Ok(if_addrs) => if_addrs,
        Err(_) => return None,
    };

    // Look for the first non-loopback IPv4 address
    for if_addr in if_addrs {
        let k = if_addr.addr;
        match k {
            IfAddr::V4(ifa) => { return Some(ifa.ip); }
            IfAddr::V6(_) => {}
        }
    }

    None
}


impl ArpPacket {
    /*pub fn new_from_bytes(data: &[u8]) -> Option<Self> {
        match parse_arp_packet(data) {
            Ok((_, arp)) => Some(arp),
            Err(_) => None,
        }
    }*/

    pub fn new_ethernet_ipv4_request(target_proto_addr: [u8; 4]) -> Self {
        let my_addr = get_my_ipv4_protocol_address().unwrap();

        let sender_hw_addr = get_mac_address().unwrap().unwrap().bytes();
        let sender_proto_addr = my_addr.octets();

        Self {
            hardware_type: 0x0001,
            protocol_type: 0x0800,
            header_len: 0x06,
            protocol_len: 0x04,
            operation: 0x0001,
            sender_hw_addr,
            sender_proto_addr,
            target_hw_addr: [0, 0, 0, 0, 0, 0],
            target_proto_addr,
        }
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut result = [0; 28];

        result[0..2].copy_from_slice(&self.hardware_type.to_be_bytes());
        result[2..4].copy_from_slice(&self.protocol_type.to_be_bytes());
        result[4] = self.header_len;
        result[5] = self.protocol_len;
        result[6..8].copy_from_slice(&self.operation.to_be_bytes());
        result[8..14].copy_from_slice(&self.sender_hw_addr);
        result[14..18].copy_from_slice(&self.sender_proto_addr);
        result[18..24].copy_from_slice(&self.target_hw_addr);
        result[24..28].copy_from_slice(&self.target_proto_addr);

        result
    }
}

/*// Parse an ARP packet
fn parse_arp_packet(input: &[u8]) -> IResult<&[u8], ArpPacket> {
    let (input, hardware_type) = be_u16(input)?;
    let (input, protocol_type) = be_u16(input)?;
    let (input, hlen) = take(1usize)(input)?;
    let (input, plen) = take(1usize)(input)?;
    let (input, operation) = be_u16(input)?;
    let (input, sender_hw_addr1) = take(6usize)(input)?;
    let (input, sender_proto_addr) = be_u32(input)?;
    let (input, target_hw_addr) = take(6usize)(input)?;
    let (input, target_proto_addr) = be_u32(input)?;

    let arp = ArpPacket {
        hardware_type,
        protocol_type,
        header_len: hlen[0],
        protocol_len: plen[0],
        operation,
        sender_hw_addr: <[u8; 6]>::try_from(sender_hw_addr1).unwrap(),
        sender_proto_addr,
        target_hw_addr: <[u8; 6]>::try_from(target_hw_addr).unwrap(),
        target_proto_addr,
    };

    Ok((input, arp))
}*/
