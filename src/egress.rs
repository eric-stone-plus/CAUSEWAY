//! Read-only observation of the kernel's ordinary preferred default routes.
//!
//! CAUSEWAY never changes this state. The signature is deliberately limited
//! to the lowest-metric default routes in each address family: adding or
//! removing a worse backup route must not churn established data planes.
//! `/proc` does not describe the source, mark, or policy-rule lookup that a
//! particular adapter socket will take; full-path health remains the fallback
//! for those configurations.

use std::time::{Duration, Instant};

use anyhow::Context;

const IPV4_ROUTES: &str = "/proc/net/route";
const IPV6_ROUTES: &str = "/proc/net/ipv6_route";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DefaultRoute {
    interface: String,
    gateway: String,
    metric: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EgressSignature {
    ipv4: Vec<DefaultRoute>,
    ipv6: Vec<DefaultRoute>,
}

impl EgressSignature {
    pub(crate) fn has_default_route(&self) -> bool {
        !self.ipv4.is_empty() || !self.ipv6.is_empty()
    }
}

pub(crate) async fn read_signature() -> anyhow::Result<EgressSignature> {
    let (ipv4, ipv6) = tokio::try_join!(
        tokio::fs::read_to_string(IPV4_ROUTES),
        tokio::fs::read_to_string(IPV6_ROUTES)
    )
    .context("read kernel default-route state")?;
    Ok(parse_signature(&ipv4, &ipv6))
}

fn preferred(mut routes: Vec<DefaultRoute>) -> Vec<DefaultRoute> {
    let Some(metric) = routes.iter().map(|route| route.metric).min() else {
        return routes;
    };
    routes.retain(|route| route.metric == metric);
    routes.sort();
    routes.dedup();
    routes
}

fn parse_signature(ipv4: &str, ipv6: &str) -> EgressSignature {
    EgressSignature {
        ipv4: preferred(parse_ipv4_defaults(ipv4)),
        ipv6: preferred(parse_ipv6_defaults(ipv6)),
    }
}

fn parse_ipv4_defaults(text: &str) -> Vec<DefaultRoute> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            if flags & 0x1 == 0 {
                return None;
            }
            Some(DefaultRoute {
                interface: fields[0].to_string(),
                gateway: fields[2].to_ascii_lowercase(),
                metric: fields[6].parse().ok()?,
            })
        })
        .collect()
}

fn parse_ipv6_defaults(text: &str) -> Vec<DefaultRoute> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
                || fields[2] != "00000000000000000000000000000000"
                || fields[3] != "00"
            {
                return None;
            }
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            if flags & 0x1 == 0 {
                return None;
            }
            Some(DefaultRoute {
                interface: fields[9].to_string(),
                gateway: fields[4].to_ascii_lowercase(),
                metric: u32::from_str_radix(fields[5], 16).ok()?,
            })
        })
        .collect()
}

/// Debounces route-manager transients and limits rebuild frequency. A
/// delivered transition advances the baseline even if the caller later
/// declines it because another mutation owns the supervisor locks; retrying
/// an old observation after that mutation would be less safe than waiting for
/// the next real egress transition.
pub(crate) struct StableEgressObserver {
    stable_for: Duration,
    cooldown: Duration,
    baseline: Option<EgressSignature>,
    candidate: Option<(EgressSignature, Instant)>,
    last_transition: Option<Instant>,
}

impl StableEgressObserver {
    pub(crate) fn new(stable_for: Duration, cooldown: Duration) -> Self {
        Self {
            stable_for,
            cooldown,
            baseline: None,
            candidate: None,
            last_transition: None,
        }
    }

    pub(crate) fn observe(
        &mut self,
        signature: EgressSignature,
        now: Instant,
    ) -> Option<EgressSignature> {
        let Some(baseline) = self.baseline.as_ref() else {
            self.baseline = Some(signature);
            return None;
        };
        if baseline == &signature {
            self.candidate = None;
            return None;
        }

        // A route manager may publish IPv4 and IPv6 in separate steps. Once
        // one stable transition has fired, fold every further signature into
        // the baseline during the cooldown instead of scheduling a delayed
        // second rebuild for the same physical handover.
        if self
            .last_transition
            .is_some_and(|last| now.duration_since(last) < self.cooldown)
        {
            self.baseline = Some(signature);
            self.candidate = None;
            return None;
        }

        match self.candidate.as_mut() {
            Some((candidate, _)) if candidate == &signature => {}
            _ => {
                self.candidate = Some((signature, now));
                return None;
            }
        }
        let (_, first_seen) = self.candidate.as_ref().expect("candidate was set above");
        if now.duration_since(*first_seen) < self.stable_for {
            return None;
        }

        let (confirmed, _) = self.candidate.take().expect("candidate was checked above");
        self.baseline = Some(confirmed.clone());
        if confirmed.has_default_route() {
            self.last_transition = Some(now);
            Some(confirmed)
        } else {
            // There is nothing useful to rebuild while the host has no
            // default route. Advancing the baseline means restoration is the
            // transition that will be debounced and delivered.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(interface: &str) -> EgressSignature {
        EgressSignature {
            ipv4: vec![DefaultRoute {
                interface: interface.to_string(),
                gateway: "0100000a".to_string(),
                metric: 100,
            }],
            ipv6: Vec::new(),
        }
    }

    fn dual_stack_signature(ipv4_interface: &str, ipv6_interface: &str) -> EgressSignature {
        let mut value = signature(ipv4_interface);
        value.ipv6.push(DefaultRoute {
            interface: ipv6_interface.to_string(),
            gateway: "fe800000000000000000000000000001".to_string(),
            metric: 100,
        });
        value
    }

    #[test]
    fn parsers_keep_only_preferred_defaults() {
        let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0\n\
eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n\
eth0 0000000A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n";
        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000258 00000000 00000000 00000001 wlan0\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000064 00000000 00000000 00000001 eth0\n";
        let parsed = parse_signature(ipv4, ipv6);
        assert_eq!(parsed.ipv4, signature("eth0").ipv4);
        assert_eq!(parsed.ipv6.len(), 1);
        assert_eq!(parsed.ipv6[0].interface, "eth0");
        assert_eq!(parsed.ipv6[0].metric, 100);
    }

    #[test]
    fn backup_route_changes_do_not_change_signature() {
        let base = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n";
        let with_backup = format!("{base}wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0\n");
        assert_eq!(parse_signature(base, ""), parse_signature(&with_backup, ""));
    }

    #[test]
    fn observer_requires_stability_and_cooldown() {
        let start = Instant::now();
        let mut observer =
            StableEgressObserver::new(Duration::from_secs(10), Duration::from_secs(30));
        assert!(observer.observe(signature("old"), start).is_none());
        assert!(observer
            .observe(signature("transient"), start + Duration::from_secs(2))
            .is_none());
        assert!(observer
            .observe(signature("old"), start + Duration::from_secs(5))
            .is_none());
        assert!(observer
            .observe(signature("new"), start + Duration::from_secs(6))
            .is_none());
        assert!(observer
            .observe(signature("new"), start + Duration::from_secs(15))
            .is_none());
        assert_eq!(
            observer.observe(signature("new"), start + Duration::from_secs(16)),
            Some(signature("new"))
        );

        assert!(observer
            .observe(signature("old"), start + Duration::from_secs(20))
            .is_none());
        assert!(observer
            .observe(signature("old"), start + Duration::from_secs(31))
            .is_none());
        assert!(observer
            .observe(signature("old"), start + Duration::from_secs(46))
            .is_none());

        assert!(observer
            .observe(signature("third"), start + Duration::from_secs(47))
            .is_none());
        assert_eq!(
            observer.observe(signature("third"), start + Duration::from_secs(57)),
            Some(signature("third"))
        );
    }

    #[test]
    fn staggered_dual_stack_publication_causes_only_one_rebuild() {
        let start = Instant::now();
        let old = dual_stack_signature("old4", "old6");
        let ipv4_moved = dual_stack_signature("new4", "old6");
        let both_moved = dual_stack_signature("new4", "new6");
        let mut observer =
            StableEgressObserver::new(Duration::from_secs(10), Duration::from_secs(30));

        assert!(observer.observe(old, start).is_none());
        assert!(observer
            .observe(ipv4_moved.clone(), start + Duration::from_secs(1))
            .is_none());
        assert_eq!(
            observer.observe(ipv4_moved, start + Duration::from_secs(11)),
            Some(dual_stack_signature("new4", "old6"))
        );

        // IPv6 arrives after IPv4 has already triggered the physical-handover
        // rebuild. Cooldown absorbs it into the baseline instead of queuing a
        // second rebuild for when the cooldown expires.
        assert!(observer
            .observe(both_moved.clone(), start + Duration::from_secs(12))
            .is_none());
        assert!(observer
            .observe(both_moved, start + Duration::from_secs(42))
            .is_none());
    }

    #[test]
    fn no_default_is_absorbed_and_restoration_is_debounced() {
        let start = Instant::now();
        let empty = EgressSignature {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        let mut observer =
            StableEgressObserver::new(Duration::from_secs(10), Duration::from_secs(30));
        assert!(observer.observe(signature("old"), start).is_none());
        assert!(observer
            .observe(empty.clone(), start + Duration::from_secs(1))
            .is_none());
        assert!(observer
            .observe(empty, start + Duration::from_secs(11))
            .is_none());
        assert!(observer
            .observe(signature("new"), start + Duration::from_secs(12))
            .is_none());
        assert_eq!(
            observer.observe(signature("new"), start + Duration::from_secs(22)),
            Some(signature("new"))
        );
    }
}
