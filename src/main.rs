#![feature(slice_take, ip_bits)]
#![allow(dead_code)]

use std::env;

use chrono::{DateTime, Local, TimeZone, Utc};
use itertools::Itertools;
use libc;
use pcap::{Capture, Packet};

mod hdr_parser;
use hdr_parser::{FlowId, LayerStats, Parser, Proto};

mod publisher;
use publisher::Publisher;

#[derive(Default, Clone, Debug)]
struct Time {
    val: DateTime<Utc>,
}

impl From<libc::timeval> for Time {
    fn from(tv: libc::timeval) -> Self {
        let secs = tv.tv_sec as i64;
        let nanos = tv.tv_usec as u32 * 1000;
        let time = Local.timestamp_opt(secs, nanos).unwrap();
        Self {
            val: DateTime::from(time),
        }
    }
}

#[derive(Default, Clone)]
struct PacketStats {
    flow: FlowId,
    time: Time,
    size_b: u64,
    layers: [LayerStats; 4],
}

impl PacketStats {
    fn new(id: FlowId, time: Time, size_b: u64) -> Self {
        Self {
            flow: id,
            time,
            size_b,
            layers: [LayerStats::default(); 4],
        }
    }

    fn parse(pkt: Packet) -> Result<Self, String> {
        let mut parser = PacketStatsParser::new(pkt);
        parser.do_parse()?;
        Ok(parser.stats())
    }

    fn get_5tuple(&self) -> String {
        let mut proto: Proto = Proto::Unknown;
        for layer in self.layers.iter().rev() {
            if layer.proto.is_transport() {
                proto = layer.proto;
                break;
            }
        }

        if proto == Proto::Unknown {
            return "Unknown".to_string();
        }

        format!(
            "({}, {}, {:?}) --> ({}, {}, {:?})",
            self.flow.src_ip,
            self.flow.src_port,
            proto,
            self.flow.dst_ip,
            self.flow.dst_port,
            proto
        )
    }

    fn to_json_bytes(&self) -> Vec<u8> {
        format!(
            r#"
         {{
             "flow": "{}",
             "time": "{}",
             "size": {},
             "l2_proto": "{}",
             "l2_size": {},
             "l3_proto": "{}",
             "l3_size": {},
             "l4_proto": "{}",
             "l4_size": {},
             "l7_proto": "{}"
         }}
         "#,
            self.get_5tuple(),
            self.time.val.timestamp_micros(),
            self.size_b,
            self.layers[0].proto,
            self.layers[0].size_b,
            self.layers[1].proto,
            self.layers[1].size_b,
            self.layers[2].proto,
            self.layers[2].size_b,
            self.layers[3].proto,
        )
        .into_bytes()
    }
}

struct PacketStatsParser<'a> {
    pkt: Packet<'a>,
    stats: PacketStats,
}

impl<'a> PacketStatsParser<'a> {
    fn new(pkt: Packet<'a>) -> Self {
        Self {
            pkt,
            stats: PacketStats::default(),
        }
    }

    fn do_parse(&mut self) -> Result<(), String> {
        self.stats.size_b = self.pkt.header.len as u64;
        self.stats.time = Time::from(self.pkt.header.ts);

        let mut parser = Parser::new(&mut self.pkt);
        let mut curr_layer = 0;
        while parser.can_next() {
            if curr_layer >= self.stats.layers.len() {
                return Err(format!(
                    "too many layers ({}, when maximum is {})",
                    curr_layer,
                    self.stats.layers.len(),
                ));
            }
            let layer = parser
                .next()
                .map_err(|err| format!("parser error: {}", err.to_string()))?;
            self.stats.layers[curr_layer] = layer;
            curr_layer += 1;
        }

        self.stats.flow = parser.flow;

        Ok(())
    }

    fn stats(&self) -> PacketStats {
        self.stats.clone()
    }
}

fn open_capture() -> Result<Capture<pcap::Offline>, String> {
    let file_path = env::args()
        .nth(1)
        .ok_or("invalid args (must be a path to the pcap-file)")?;

    Capture::from_file(&file_path).map_err(|err| {
        format!(
            "failed to open pcap-file ('{}'): {}",
            file_path,
            err.to_string()
        )
    })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let publisher = Publisher::connect("localhost", 5672, "pcapan", "pass1").await?;
    println!("Connected to RabbitMQ");

    let mut cap = open_capture()?;
    println!("Opened capture");

    let mut handled = 0usize;
    while let Ok(packet) = cap.next_packet() {
        let stats = PacketStats::parse(packet)?;

        #[cfg(debug_assertions)]
        println!(
            "pkt #{} (flow={}), size={}B, time={:?}, layers=[{}]",
            handled,
            stats.get_5tuple(),
            stats.size_b,
            stats.time,
            stats.layers.iter().format(", ")
        );

        let data = stats.to_json_bytes();
        publisher.send(data).await?;

        handled += 1;
    }

    publisher.wait_all_sends().await;

    println!("Handled {} pkts", handled);

    Ok(())
}
