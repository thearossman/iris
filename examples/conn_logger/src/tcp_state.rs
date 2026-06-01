/// Per-connection TCP flag and end-reason tracking.
///
/// Records non-SYN/ACK flag bits seen over the connection lifetime and
/// whether a FIN or RST was observed (used to classify the end reason).
use iris_compiler::*;
use iris_core::protocols::packet::tcp::{ACK, FIN, PSH, RST, SYN, TCP_PROTOCOL, URG};
use iris_core::L4Pdu;

#[datatype]
#[derive(Debug)]
pub struct TcpFlowState {
    /// Bitmask of non-SYN/ACK flag bits seen (URG, PSH, RST, FIN).
    pub tcp_flags_seen: u8,
    pub saw_fin: bool,
    pub saw_rst: bool,
    is_tcp: bool,
}

impl TcpFlowState {
    pub fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            tcp_flags_seen: 0,
            saw_fin: false,
            saw_rst: false,
            is_tcp: first_pkt.ctxt.proto == TCP_PROTOCOL,
        }
    }

    pub fn end_reason(&self) -> &'static str {
        if self.saw_rst {
            "RST"
        } else if self.saw_fin {
            "FIN"
        } else {
            "Timeout"
        }
    }

    pub fn flag_names(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.tcp_flags_seen & URG != 0 {
            flags.push("URG");
        }
        if self.tcp_flags_seen & PSH != 0 {
            flags.push("PSH");
        }
        if self.tcp_flags_seen & RST != 0 {
            flags.push("RST");
        }
        if self.tcp_flags_seen & FIN != 0 {
            flags.push("FIN");
        }
        flags
    }

    #[datatype_fn("TcpFlowState,level=InL4Conn")]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if !self.is_tcp {
            return;
        }
        let flags = pdu.flags();
        let is_pure_ack = flags == ACK && pdu.length() == 0;
        let is_syn_or_synack = flags == SYN || flags == (SYN | ACK);
        if !is_pure_ack && !is_syn_or_synack {
            self.tcp_flags_seen |= flags & !(SYN | ACK);
        }
        if flags & FIN != 0 {
            self.saw_fin = true;
        }
        if flags & RST != 0 {
            self.saw_rst = true;
        }
    }
}
