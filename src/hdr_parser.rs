use std::{collections::HashMap, fmt::Display, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use pcap::Packet;

type Port = u16;

#[derive(Clone)]
pub struct FlowId {
    pub src_port: Port,
    pub dst_port: Port,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

impl Default for FlowId {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Proto {
    #[default]
    NotExist,
    NotImplemented,
    Http,
    Dns,
    Ssdp,
    Quic,
    Tls,
    Tcp,
    Udp,
    Icmp,
    Ipv4,
    Ipv6,
    Arp,
    Ethernet,
}

impl Proto {
    pub fn is_transport(self) -> bool {
        match self {
            Proto::Quic | Proto::Tls | Proto::Tcp | Proto::Udp => true,
            _ => false,
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct LayerStats {
    pub proto: Proto,
    pub size_b: u64,
}

impl LayerStats {
    pub fn new(proto: Proto, size_b: u64) -> Self {
        Self { proto, size_b }
    }
}

impl Display for LayerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("({:?}, sz={})", self.proto, self.size_b))
    }
}

pub enum ParserErrorType {
    InvalidSize,
    UnknownProto,
    CantNext,
}

pub struct ParserError {
    ty: ParserErrorType,
    details: String,
}

impl ParserError {
    fn invalid_size(proto: Proto, sz: usize, begin: usize, end: usize) -> Self {
        let details = format!(
            "invalid pkt size for proto '{:?}': actual size is {}, expected slice is [{}, {})",
            proto, sz, begin, end
        );
        Self {
            ty: ParserErrorType::InvalidSize,
            details,
        }
    }

    fn unknown_proto(proto: Proto) -> Self {
        Self {
            ty: ParserErrorType::UnknownProto,
            details: format!("unknown proto '{:?}'", proto),
        }
    }

    fn cant_next() -> Self {
        Self {
            ty: ParserErrorType::CantNext,
            details: "parser can't continue".to_string(),
        }
    }
}

impl ToString for ParserError {
    fn to_string(&self) -> String {
        self.details.clone()
    }
}

pub struct Parser<'a, 'b> {
    pkt: &'a mut Packet<'b>,
    pkt_len: u64,
    pkt_caplen: u64,
    pub flow: FlowId,
    protos: HashMap<Proto, Box<dyn ProtoParser>>,
    next_proto: Option<Proto>,
}

impl<'a, 'b> Parser<'a, 'b> {
    pub fn new(pkt: &'a mut Packet<'b>) -> Self {
        let pkt_len = pkt.header.len as u64;
        let pkt_caplen = pkt.header.caplen as u64;

        let mut this = Self {
            pkt,
            pkt_len,
            pkt_caplen,
            flow: FlowId::default(),
            protos: HashMap::new(),
            next_proto: Some(Proto::Ethernet),
        };

        let protos: Vec<Box<dyn ProtoParser>> = vec![
            Box::new(PayloadParser::new(Proto::NotImplemented)),
            Box::new(PayloadParser::new(Proto::Http)),
            Box::new(PayloadParser::new(Proto::Quic)),
            Box::new(PayloadParser::new(Proto::Tls)),
            Box::new(TcpParser::new()),
            Box::new(UdpParser::new()),
            Box::new(IcmpParser::new()),
            Box::new(Ipv4Parser::new()),
            Box::new(Ipv6Parser::new()),
            Box::new(ArpParser::new()),
            Box::new(EthernetParser::new()),
        ];
        for proto in protos {
            this.protos.insert(proto.name(), proto);
        }
        this
    }

    pub fn next(&mut self) -> Result<LayerStats, ParserError> {
        let proto = self.next_proto.ok_or_else(|| ParserError::cant_next())?;

        let proto_parser = match self.protos.get(&proto) {
            Some(v) => v,
            None => return Err(ParserError::unknown_proto(proto)),
        };

        let hdr_sz = proto_parser.parse_hdr_size(self.pkt)?;
        let curr_pkt_len = self.pkt_len;
        self.next_proto = proto_parser.detect_next(self.pkt)?;

        proto_parser.try_parse_flow_id(self.pkt, &mut self.flow)?;

        self.pkt_len -= hdr_sz;
        self.pkt_caplen -= hdr_sz;
        let _ = self.pkt.data.take(..(hdr_sz as usize));

        Ok(LayerStats::new(proto, curr_pkt_len as u64))
    }

    pub fn can_next(&self) -> bool {
        self.pkt_caplen > 0 && self.next_proto.is_some()
    }
}

trait ProtoParser {
    fn name(&self) -> Proto;
    fn parse_hdr_size(&self, pkt: &Packet) -> Result<u64, ParserError>;
    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError>;
    fn try_parse_flow_id(&self, _pkt: &Packet, _flow: &mut FlowId) -> Result<(), ParserError> { Ok(()) }
}

struct FieldParser;

impl FieldParser {
    fn parse<'a, T: From<&'a [u8]>>(
        pkt: &'a Packet,
        proto: Proto,
        size: u8,
        offset: u8,
    ) -> Result<T, ParserError> {
        let data = pkt.data;
        let begin = offset as usize;
        let end = begin + size as usize;
        let val = data.get(begin..end);
        match val {
            Some(v) => Ok(T::from(v)),
            None => Err(ParserError::invalid_size(proto, data.len(), begin, end)),
        }
    }
}

struct Integer(u64);

impl From<&[u8]> for Integer {
    fn from(value: &[u8]) -> Self {
        let mut res: u64 = 0;
        let mut i = 0;
        for v  in value {
            let shift = (value.len() - i - 1) * 8;
            res |= (*v as u64) << shift;
            i += 1;
        }
        Integer { 0: res }
    }
}

struct EthernetParser;
struct ArpParser;
struct Ipv4Parser;
struct Ipv6Parser;
struct IcmpParser;
struct TcpParser;
struct UdpParser;
struct PayloadParser(Proto);

struct EtherType(u16);

impl Into<Proto> for EtherType {
    fn into(self) -> Proto {
        match self.0 {
            0x0800 => Proto::Ipv4,
            0x0806 => Proto::Arp,
            0x86DD => Proto::Ipv6,
            _ => Proto::NotImplemented,
        }
    }
}

impl From<&[u8]> for EtherType {
    fn from(value: &[u8]) -> Self {
        let first_byte = value[0] as u16;
        let second_byte = value[1] as u16;
        let v = ((first_byte << 8) | second_byte) as u16;
        unsafe { std::mem::transmute(v) }
    }
}

impl EthernetParser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for EthernetParser {
    fn name(&self) -> Proto {
        Proto::Ethernet
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(14)
    }

    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        FieldParser::parse::<EtherType>(pkt, self.name(), 2, 12).map(|p| Some(p.into()))
    }
}

impl ArpParser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for ArpParser {
    fn name(&self) -> Proto {
        Proto::Arp
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(28)
    }

    fn detect_next(&self, _pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        Ok(None)
    }
}

struct IpProto(u8);

impl Into<Proto> for IpProto {
    fn into(self) -> Proto {
        match self.0 {
            1 => Proto::Icmp,
            6 => Proto::Tcp,
            17 => Proto::Udp,
            58 => Proto::Icmp,
            _ => Proto::NotImplemented,
        }
    }
}

impl From<&[u8]> for IpProto {
    fn from(value: &[u8]) -> Self {
        let v = value[0] as u8;
        unsafe { std::mem::transmute(v) }
    }
}

impl Ipv4Parser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for Ipv4Parser {
    fn name(&self) -> Proto {
        Proto::Ipv4
    }

    fn parse_hdr_size(&self, pkt: &Packet) -> Result<u64, ParserError> {
        let ver_ihl = FieldParser::parse::<Integer>(pkt, self.name(), 1, 0).map(|v| v.0)?;
        let size_32word = (ver_ihl & 0x0f) as u64;
        Ok(size_32word * 4)
    }

    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        FieldParser::parse::<IpProto>(pkt, self.name(), 1, 9).map(|p| Some(p.into()))
    }

    fn try_parse_flow_id(&self, pkt: &Packet, flow: &mut FlowId) -> Result<(), ParserError> {
        let src = FieldParser::parse::<Integer>(pkt, self.name(), 4, 12)?.0 as u32;
        let dst = FieldParser::parse::<Integer>(pkt, self.name(), 4, 16)?.0 as u32;
        flow.src_ip = IpAddr::V4(Ipv4Addr::from_bits(src));
        flow.dst_ip = IpAddr::V4(Ipv4Addr::from_bits(dst));
        Ok(())
    }
}

impl Ipv6Parser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for Ipv6Parser {
    fn name(&self) -> Proto {
        Proto::Ipv6
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(40)
    }

    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        FieldParser::parse::<IpProto>(pkt, self.name(), 1, 6).map(|p| Some(p.into()))
    }

    fn try_parse_flow_id(&self, pkt: &Packet, flow: &mut FlowId) -> Result<(), ParserError> {
        let src_1 = FieldParser::parse::<Integer>(pkt, self.name(), 8, 8)?.0 as u128;
        let src_2 = FieldParser::parse::<Integer>(pkt, self.name(), 8, 16)?.0 as u128;
        let dst_1 = FieldParser::parse::<Integer>(pkt, self.name(), 8, 24)?.0 as u128;
        let dst_2 = FieldParser::parse::<Integer>(pkt, self.name(), 8, 32)?.0 as u128;

        flow.src_ip = IpAddr::V6(Ipv6Addr::from_bits((src_1 << 64) | src_2));
        flow.dst_ip = IpAddr::V6(Ipv6Addr::from_bits((dst_1 << 64) | dst_2));

        Ok(())
    }
}

impl IcmpParser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for IcmpParser {
    fn name(&self) -> Proto {
        Proto::Icmp
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(8)
    }

    fn detect_next(&self, _pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        Ok(None)
    }
}

impl TcpParser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for TcpParser {
    fn name(&self) -> Proto {
        Proto::Tcp
    }

    fn parse_hdr_size(&self, pkt: &Packet) -> Result<u64, ParserError> {
        let sz = FieldParser::parse::<Integer>(pkt, self.name(), 1, 96 / 8).map(|v| v.0)?;
        Ok((sz & 0x0f) as u64)
    }

    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        let mut flow = FlowId::default();
        self.try_parse_flow_id(pkt, &mut flow)
            .map(|_| None as Option<Proto>)?;

        let proto = if flow.src_port == 443 || flow.dst_port == 443 {
            Some(Proto::Tls)
        } else if flow.src_port == 80 || flow.dst_port == 80 {
            Some(Proto::Http)
        } else {
            None
        };

        Ok(proto)
    }

    fn try_parse_flow_id(&self, pkt: &Packet, flow: &mut FlowId) -> Result<(), ParserError> {
        flow.src_port = FieldParser::parse::<Integer>(pkt, self.name(), 2, 0)?.0 as Port;
        flow.dst_port = FieldParser::parse::<Integer>(pkt, self.name(), 2, 2)?.0 as Port;
        Ok(())
    }
}

impl UdpParser {
    fn new() -> Self {
        Self {}
    }
}

impl ProtoParser for UdpParser {
    fn name(&self) -> Proto {
        Proto::Udp
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(8)
    }

    fn detect_next(&self, pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        let mut flow = FlowId::default();
        self.try_parse_flow_id(pkt, &mut flow)
            .map(|_| None as Option<Proto>)?;

        let proto = if flow.src_port == 443 || flow.dst_port == 443 {
            Some(Proto::Quic)
        } else {
            None
        };

        Ok(proto)
    }

    fn try_parse_flow_id(&self, pkt: &Packet, flow: &mut FlowId) -> Result<(), ParserError> {
        flow.src_port = FieldParser::parse::<Integer>(pkt, self.name(), 2, 0)?.0 as Port;
        flow.dst_port = FieldParser::parse::<Integer>(pkt, self.name(), 2, 2)?.0 as Port;
        Ok(())
    }
}

impl PayloadParser {
    fn new(proto: Proto) -> Self {
        Self { 0: proto }
    }
}

impl ProtoParser for PayloadParser {
    fn name(&self) -> Proto {
        self.0
    }

    fn parse_hdr_size(&self, _pkt: &Packet) -> Result<u64, ParserError> {
        Ok(0)
    }

    fn detect_next(&self, _pkt: &Packet) -> Result<Option<Proto>, ParserError> {
        Ok(None)
    }
}
