use std::fmt;
use mac_address::get_mac_address;
use crate::{IPV4};

#[repr(C, packed)]
pub(crate) struct EthernetFrame {
    pub(crate) destination_address: [u8; 6],
    pub(crate) source_address: [u8; 6],
    pub(crate) ether_type: [u8; 2],
    pub(crate) payload: Vec<u8>,
}

impl EthernetFrame {
    pub(crate) fn new(destination_address: [u8; 6], payload: Vec<u8>) -> EthernetFrame {

        let source_address = get_mac_address().unwrap().unwrap().bytes();
        EthernetFrame {
            destination_address,
            source_address,
            ether_type: [0x08, 0x06],
            payload,
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.destination_address);
        buffer.extend_from_slice(&self.source_address);
        buffer.extend_from_slice(&self.ether_type);
        buffer.extend_from_slice(&self.payload);

        buffer
    }
}


impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ETHER: -----Ether Header-----\n")?;
        write!(f, "ETHER:\n")?;
        write!(f, "ETHER: Destination= {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.destination_address[0],
               self.destination_address[1], self.destination_address[2], self.destination_address[3],
               self.destination_address[4], self.destination_address[5])?;
        write!(f, "ETHER: Source     = {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.source_address[0],
               self.source_address[1], self.source_address[2], self.source_address[3],
               self.source_address[4], self.source_address[5])?;
        write!(f, "ETHER: Ethertype  = 0x{:x}{:x}\n", self.ether_type[0], self.ether_type[1])?;
        write!(f, "ETHER:")
    }
}