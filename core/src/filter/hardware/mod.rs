mod flow_action;
mod flow_attr;
mod flow_item;

use self::flow_action::*;
use self::flow_attr::*;
use self::flow_item::*;

use super::ast::*;
use super::pattern::*;
use super::pred_ptree::PredPTree;
use super::Filter;

use crate::dpdk;
use crate::port::*;

use std::ffi::{c_void, CStr};
use std::fmt;
use std::mem;

use anyhow::{bail, Result};
use log::{debug, error, info, warn};
use thiserror::Error;

// priority levels for ingress rules (lower number = checked first)
const EXCLUDE_PRIORITY: u32 = 0;
const HIGH_PRIORITY: u32 = 1;
const LOW_PRIORITY: u32 = 3;

#[derive(Debug)]
pub(crate) struct HardwareFilter<'a> {
    patterns: Vec<LayeredPattern>,
    // `!=` predicates realized as redirect rules: exact-match on the
    // excluded value, jumping to the default drop table instead of RSS.
    // Installed ahead of `patterns` (see `install`), since a NIC can't
    // match a negation directly.
    exclude_patterns: Vec<LayeredPattern>,
    port: &'a Port,
}

impl<'a> HardwareFilter<'a> {
    // Creates a new HardwareFilter for port given a filter.
    // Prunes all predicates not supported by the device.
    pub(crate) fn new(filter: &Filter, port: &'a Port) -> Self {
        let original_patterns = filter.get_patterns_flat();

        let hw_patterns = original_patterns
            .iter()
            .map(|p| p.retain_hardware_predicates(port))
            .collect::<Vec<_>>();

        // Prune some redundant patterns.
        // \note This does not do the parent-child sorting of the SW filter;
        // this seems to be ok for Iris's current scale
        // (applying NIC rules is fast and we're not hitting NIC limits)
        let mut hw_ptree = PredPTree::new(&hw_patterns, true);
        hw_ptree.prune_branches();
        let mut hw_patterns = hw_ptree.to_flat_patterns();

        let mut layered = vec![];
        for pattern in hw_patterns.iter_mut() {
            // Only retaining hardware filterable predicates may make
            // a pattern no-longer fully qualified. Therefore, we must
            // broaden pattern until hardware filterable again
            while !pattern.is_fully_qualified() {
                pattern.predicates.pop();
            }
            // converts to LayeredPattern
            layered.extend(pattern.to_fully_qualified().expect("fully qualified"));
        }

        // Remove identical patterns
        layered.sort();
        layered.dedup();

        // `retain_hardware_predicates` drops `!=` predicates above, since a
        // NIC can't match a negation directly. Build a redirect rule for
        // each one instead -- see `hw_excludable`/`install`.
        let mut exclude_patterns = vec![];
        for pattern in original_patterns.iter() {
            for pred in pattern.predicates.iter() {
                let Some(excl_pred) = hw_excludable(pred, port) else {
                    continue;
                };
                // Only safe if no other disjunct in the filter would still
                // accept this value -- e.g. "udp and udp.port != 1234" next
                // to "udp and udp.port != 5246" from another subscription.
                // Neither pattern subsumes the other, so both stick around
                // as separate disjuncts, and the second one still wants
                // port 1234 traffic.
                if !globally_excludable(&excl_pred, &original_patterns) {
                    continue;
                }
                let excl_pattern = FlatPattern {
                    predicates: vec![
                        Predicate::Unary {
                            protocol: excl_pred.get_protocol().clone(),
                        },
                        excl_pred,
                    ],
                    as_str: None,
                };
                if let Ok(fq) = excl_pattern.to_fully_qualified() {
                    exclude_patterns.extend(fq);
                }
            }
        }
        exclude_patterns.sort();
        exclude_patterns.dedup();

        HardwareFilter {
            patterns: layered,
            exclude_patterns,
            port,
        }
    }

    // Installs the hardware filter to the port.
    pub(crate) fn install(&self) -> Result<()> {
        debug!("{}", self);
        if self.patterns.iter().all(|p| p.is_empty())
            && self.exclude_patterns.iter().all(|p| p.is_empty())
        {
            info!("Empty filter, skipping.");
            return Ok(());
        }

        info!("Applying hardware filter rules on Port {}...", self.port.id);
        // Exclusions go in first, ahead of the accept patterns they carve
        // exceptions out of.
        for pattern in self.exclude_patterns.iter() {
            install_redirect_pattern(pattern, self.port, 0, EXCLUDE_PRIORITY, 1)?;
        }
        for pattern in self.patterns.iter() {
            install_pattern(pattern, self.port, 0, HIGH_PRIORITY)?;
        }
        // Non-matching traffic will be dropped by default on table 1
        // Redirect is faster than using a default DROP rule
        add_redirect(self.port, 0, 1, LOW_PRIORITY)?;
        // drop_eth_traffic(self.port, 0, LOW_PRIORITY)?;

        Ok(())
    }
}

impl fmt::Display for HardwareFilter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "[HardwareFilter]: ")?;
        for pattern in self.exclude_patterns.iter() {
            writeln!(f, "REDIRECT (!=) {}", pattern.to_flat_pattern())?;
        }
        for pattern in self.patterns.iter() {
            writeln!(f, "{}", pattern.to_flat_pattern())?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub(crate) enum HardwareFilterError {
    #[error("Rule validation for {lpattern} failed on creation attempt. Reason: {reason}")]
    Validation {
        lpattern: LayeredPattern,
        reason: String,
    },

    #[error("Rule for {lpattern} validated but failed creation. Reason: {reason}")]
    Creation {
        lpattern: LayeredPattern,
        reason: String,
    },

    #[error("Hardware flow rule invalid: {0}")]
    InvalidRule(LayeredPattern),
}

pub(crate) fn device_supported(pred: &Predicate, port: &Port) -> bool {
    // Device supported protocols
    let hw_filterable_protos = hashset! {
        protocol!("ipv4"),
        protocol!("ipv6"),
        protocol!("tcp"),
        protocol!("udp"),
    };
    let proto_supported = hw_filterable_protos.contains(pred.get_protocol());
    if !proto_supported {
        info!("Hardware filter does not support protocol for: [{}]", pred);
        return false;
    }

    // Only allow equality predicates
    // MLX5 only supports equality or masked IP address
    let op_supported = match pred {
        Predicate::Unary { .. } => true,
        Predicate::Binary {
            protocol,
            field: _,
            op,
            value: _,
        } => {
            matches!(op, BinOp::Eq)
                || protocol == &protocol!("ipv4") && matches!(op, BinOp::In)
                || protocol == &protocol!("ipv6") && matches!(op, BinOp::In)
        }
        _ => false,
    };
    if !op_supported {
        info!(
            "Hardware filter does not support binary comparison operator for: [{}]",
            pred
        );
        return false;
    }

    // The only way to truly tell if predicate on a field is supported is to
    // fully-qualify it and test if all fully-qualified patterns validate successfully.
    // This still does not guarantee the flow rule will create successfully.
    // For example, a collision detected or device resource limitations.
    // Hardware Rules are created on table 0 (group 0) with high priority
    // matching.
    let pred_supported = predicate_supported(pred, port, 0, HIGH_PRIORITY);
    if !pred_supported {
        info!("Hardware filter does not support predicate: [{}]", pred);
        return false;
    }
    true
}

// NICs can't match a `!=` directly -- MLX5 only has equality/masked
// matches, no "not equal" primitive. If `pred` is a `!=` on a hardware
// protocol, this returns the equivalent `Eq` predicate on the excluded
// value, which `HardwareFilter::new` turns into a higher-priority redirect
// rule instead (see `install`).
fn hw_excludable(pred: &Predicate, port: &Port) -> Option<Predicate> {
    let Predicate::Binary {
        protocol,
        field,
        op: BinOp::Ne,
        value,
    } = pred
    else {
        return None;
    };
    let hw_filterable_protos = hashset! {
        protocol!("ipv4"),
        protocol!("ipv6"),
        protocol!("tcp"),
        protocol!("udp"),
    };
    if !hw_filterable_protos.contains(protocol) {
        return None;
    }
    let eq_pred = Predicate::Binary {
        protocol: protocol.clone(),
        field: field.clone(),
        op: BinOp::Eq,
        value: value.clone(),
    };
    predicate_supported(&eq_pred, port, 0, EXCLUDE_PRIORITY).then_some(eq_pred)
}

// True if no disjunct of the filter would accept `excl_pred`'s value (the
// disjunct `excl_pred` came from doesn't count -- it trivially excludes its
// own value). Two disjuncts excluding different values, e.g. "udp.port !=
// 1234" next to "udp.port != 5246" from another subscription, don't
// collapse into each other, so the second one still wants port 1234
// traffic; dropping it in hardware would disagree with the software
// filter. `FlatPattern::is_excl` already answers "can these two patterns
// ever both match the same packet", so just reuse it.
fn globally_excludable(excl_pred: &Predicate, all_patterns: &[FlatPattern]) -> bool {
    let singleton = FlatPattern {
        predicates: vec![excl_pred.clone()],
        as_str: None,
    };
    all_patterns.iter().all(|p| p.is_excl(&singleton))
}

fn predicate_supported(predicate: &Predicate, port: &Port, group: u32, priority: u32) -> bool {
    let pattern = FlatPattern {
        predicates: vec![predicate.to_owned()],
        as_str: None,
    };
    let fq_patterns = pattern.to_fully_qualified().expect("fully qualified");
    fq_patterns
        .iter()
        .all(|p| pattern_supported(p, port, group, priority))
}

fn pattern_supported(lpattern: &LayeredPattern, port: &Port, group: u32, priority: u32) -> bool {
    let attr = FlowAttribute::new(group, priority);
    let pattern = FlowPattern::from_layered_pattern(lpattern);
    // debug!("lpattern: {}", lpattern);
    match pattern {
        Ok(mut pattern) => {
            let mut action = FlowAction::new(port.id);

            action.append_rss();
            action.finish();

            validate_rule(port, attr, &mut pattern, &mut action)
        }
        Err(error) => {
            warn!("{}", error);
            false
        }
    }
}

fn validate_rule(
    port: &Port,
    attr: FlowAttribute,
    pattern: &mut FlowPattern,
    action: &mut FlowAction,
) -> bool {
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    for item in pattern.items.iter() {
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();
        pattern_rules.push(p_item);
    }
    flow_item::append_end(&mut pattern_rules);

    // Need to update flow_action_rss here
    // reta_raw needs to stay in scope until after rte_flow_validate() succeeds
    let reta_raw = port.reta.iter().map(|q| q.raw()).collect::<Vec<_>>();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS = a.type_ {
            action.rss[0].queue_num = port.queue_map.len() as u32;
            action.rss[0].queue = reta_raw.as_ptr();
            a.conf = &action.rss[0] as *const _ as *const c_void;
        }
    }

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        ret == 0
    }
}

fn install_pattern(
    lpattern: &LayeredPattern,
    port: &Port,
    group: u32,
    priority: u32,
) -> Result<()> {
    let attr = FlowAttribute::new(group, priority);
    if let Ok(mut pattern) = FlowPattern::from_layered_pattern(lpattern) {
        let mut action = FlowAction::new(port.id);
        // action.append_mark(tag as u32);

        action.append_rss();
        action.finish();

        create_rule(lpattern, port, attr, &mut pattern, &mut action)
    } else {
        bail!(HardwareFilterError::InvalidRule(lpattern.to_owned()));
    }
}

// Same as `install_pattern`, but jumps to `to_group` instead of RSS-ing.
// For `!=` exclusions, `to_group` is the same drop table that unmatched
// traffic already falls into via `add_redirect`, so this gets the effect
// of a DROP action without actually using one.
fn install_redirect_pattern(
    lpattern: &LayeredPattern,
    port: &Port,
    group: u32,
    priority: u32,
    to_group: u32,
) -> Result<()> {
    let attr = FlowAttribute::new(group, priority);
    if let Ok(mut pattern) = FlowPattern::from_layered_pattern(lpattern) {
        let mut action = FlowAction::new(port.id);
        action.append_jump(to_group);
        action.finish();

        create_rule(lpattern, port, attr, &mut pattern, &mut action)
    } else {
        bail!(HardwareFilterError::InvalidRule(lpattern.to_owned()));
    }
}

fn create_rule(
    lpattern: &LayeredPattern,
    port: &Port,
    attr: FlowAttribute,
    pattern: &mut FlowPattern,
    action: &mut FlowAction,
) -> Result<()> {
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    for item in pattern.items.iter() {
        let mut p_item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
        p_item.type_ = item.item_type();
        p_item.spec = item.spec();
        p_item.mask = item.mask();
        pattern_rules.push(p_item);
    }
    flow_item::append_end(&mut pattern_rules);

    // Need to update flow_action_rss here
    // reta_raw needs to stay in scope until after rte_flow_create() succeeds
    let reta_raw = port.reta.iter().map(|q| q.raw()).collect::<Vec<_>>();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS = a.type_ {
            action.rss[0].queue_num = port.queue_map.len() as u32;
            action.rss[0].queue = reta_raw.as_ptr();
            a.conf = &action.rss[0] as *const _ as *const c_void;
        } else if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP = a.type_ {
            a.conf = &action.jump[0] as *const _ as *const c_void;
        }
    }

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            bail!(HardwareFilterError::Validation {
                lpattern: lpattern.to_owned(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: lpattern.to_owned(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Hardware flow rule created: {}", lpattern);
                Ok(())
            }
        }
    }
}

fn add_redirect(port: &Port, from_group: u32, to_group: u32, priority: u32) -> Result<()> {
    let attr = FlowAttribute::new(from_group, priority);

    // Pattern matches all Ethernet traffic
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    flow_item::append_end(&mut pattern_rules);

    // Set action to redirect
    let mut action = FlowAction::new(port.id);
    action.append_jump(to_group);
    action.finish();
    for a in action.rules.iter_mut() {
        if let dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP = a.type_ {
            a.conf = &action.jump[0] as *const _ as *const c_void;
        }
    }

    info!(
        "Setting port {} to redirect from group {} to {}...",
        port.id, from_group, to_group
    );

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            error!("Redirect rule failed validation: {}", msg.to_str().unwrap());
            bail!(HardwareFilterError::Validation {
                lpattern: LayeredPattern::new(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                error!("Redirect rule failed creation.");
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: LayeredPattern::new(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Created hardware flow rule for redirect.");
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn drop_eth_traffic(port: &Port, group: u32, priority: u32) -> Result<()> {
    let attr = FlowAttribute::new(group, priority);

    // Pattern matches all Ethernet traffic
    let mut pattern_rules: PatternRules = vec![];
    flow_item::append_eth(&mut pattern_rules);
    flow_item::append_end(&mut pattern_rules);

    // Set action to DROP
    let mut action = FlowAction::new(port.id);
    action.append_drop();
    action.finish();

    info!(
        "Setting port {} to drop all ethernet traffic by default...",
        port.id
    );

    let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
    unsafe {
        let ret = dpdk::rte_flow_validate(
            port.id.raw(),
            attr.raw() as *const _,
            pattern_rules.as_ptr(),
            action.rules.as_ptr(),
            &mut error as *mut _,
        );
        if ret != 0 {
            error!("Default drop rule failed validation.");
            let msg: &CStr = CStr::from_ptr(error.message);
            bail!(HardwareFilterError::Validation {
                lpattern: LayeredPattern::new(),
                reason: msg.to_str().unwrap().to_string()
            });
        } else {
            let ret = dpdk::rte_flow_create(
                port.id.raw(),
                attr.raw() as *const _,
                pattern_rules.as_ptr(),
                action.rules.as_ptr(),
                &mut error as *mut _,
            );
            if ret.is_null() {
                error!("Default drop rule failed creation.");
                let msg: &CStr = CStr::from_ptr(error.message);
                bail!(HardwareFilterError::Creation {
                    lpattern: LayeredPattern::new(),
                    reason: msg.to_str().unwrap().to_string()
                });
            } else {
                info!("Created hardware flow rule to drop ethernet traffic by default.");
            }
        }
    }
    Ok(())
}

// Flush all flow rules associated with port
pub(crate) fn flush_rules(port: &Port) {
    info!("Flushing flow rules on Port {}", port.id);
    unsafe {
        let mut error: dpdk::rte_flow_error = mem::zeroed();
        let ret = dpdk::rte_flow_flush(port.id.raw(), &mut error as &mut _);
        if ret != 0 {
            let msg: &CStr = CStr::from_ptr(error.message);
            panic!(
                "Flush rules failed. Port in inconsistent state, please restart: {}",
                msg.to_str().unwrap()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_ne_port(field: &str, value: u64) -> Predicate {
        Predicate::Binary {
            protocol: protocol!("udp"),
            field: field!(field),
            op: BinOp::Ne,
            value: Value::Int(value),
        }
    }

    fn udp_eq_port(field: &str, value: u64) -> Predicate {
        Predicate::Binary {
            protocol: protocol!("udp"),
            field: field!(field),
            op: BinOp::Eq,
            value: Value::Int(value),
        }
    }

    #[test]
    fn excludable_alone_is_safe() {
        // "udp and udp.src_port != 1234 and udp.dst_port != 1234" is the
        // only disjunct: nothing else in the filter could accept port 1234,
        // so it's safe to redirect it in hardware.
        let excluding = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 1234),
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let excl_pred = udp_eq_port("dst_port", 1234);
        assert!(globally_excludable(&excl_pred, &[excluding]));
    }

    #[test]
    fn bare_protocol_sibling_blocks_exclusion() {
        // "udp and udp.port != 1234" alongside a bare "udp" disjunct: the
        // bare pattern accepts port 1234 too, so it must NOT be dropped in
        // hardware even though one disjunct excludes it.
        let excluding = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 1234),
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let bare_udp = FlatPattern {
            predicates: vec![Predicate::Unary {
                protocol: protocol!("udp"),
            }],
            as_str: None,
        };
        let excl_pred = udp_eq_port("dst_port", 1234);
        assert!(!globally_excludable(&excl_pred, &[excluding, bare_udp]));
    }

    #[test]
    fn disjoint_protocol_sibling_is_safe() {
        // "tcp" as a sibling disjunct can never match a udp-specific
        // exclusion, so it shouldn't block hardware-dropping the port.
        let excluding = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 1234),
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let tcp_only = FlatPattern {
            predicates: vec![Predicate::Unary {
                protocol: protocol!("tcp"),
            }],
            as_str: None,
        };
        let excl_pred = udp_eq_port("dst_port", 1234);
        assert!(globally_excludable(&excl_pred, &[excluding, tcp_only]));
    }

    #[test]
    fn sibling_excluding_different_value_blocks_exclusion() {
        // A sibling that excludes a *different* port (5246) doesn't
        // restrict 1234 at all, so it would still accept port 1234 traffic
        // -- must not be dropped in hardware.
        let excluding = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 1234),
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let other_exclusion = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 5246),
                udp_ne_port("dst_port", 5246),
            ],
            as_str: None,
        };
        let excl_pred = udp_eq_port("dst_port", 1234);
        assert!(!globally_excludable(
            &excl_pred,
            &[excluding, other_exclusion]
        ));
    }

    #[test]
    fn sibling_excluding_same_value_is_safe() {
        // A sibling that excludes the *same* port is consistent -- both
        // disjuncts agree port 1234 should never reach software, so it's
        // still safe to drop in hardware.
        let excluding = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("src_port", 1234),
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let other_excluding_same = FlatPattern {
            predicates: vec![
                Predicate::Unary {
                    protocol: protocol!("udp"),
                },
                udp_ne_port("dst_port", 1234),
            ],
            as_str: None,
        };
        let excl_pred = udp_eq_port("dst_port", 1234);
        assert!(globally_excludable(
            &excl_pred,
            &[excluding, other_excluding_same]
        ));
    }
}
