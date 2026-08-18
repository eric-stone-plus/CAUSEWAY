//! Node scoring and selection: stability first.
//!
//! - The success-rate EMA is the primary metric; the RTT EMA is secondary
//!   (used only when success rates are too close to call).
//! - Stickiness (hysteresis): a challenger must beat the incumbent by a
//!   "clear margin" to trigger a switch, avoiding flip-flopping between
//!   nodes — this machine wants uptime, not the lowest latency.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Rolling statistics for a single node, persisted to the state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStats {
    /// Exponential moving average of probe success rate, [0,1]
    pub success_ema: f64,
    /// Exponential moving average of RTT (milliseconds); None if never
    /// succeeded
    pub rtt_ema_ms: Option<f64>,
    /// Most recent successful RTT samples (ms, newest last) for the
    /// latency sparkline; capped at [`RTT_HISTORY`].
    #[serde(default)]
    pub recent_rtts_ms: Vec<f64>,
    /// Consecutive health-check failures on the active path (route-level,
    /// counted separately from periodic probes)
    pub consecutive_health_failures: u32,
    /// Total probe count; 0 means never probed (unknown node)
    pub probe_count: u64,
    pub last_probe_unix: Option<i64>,
}

/// How many recent RTT samples per node survive in the state file.
pub const RTT_HISTORY: usize = 20;

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            success_ema: 0.0,
            rtt_ema_ms: None,
            recent_rtts_ms: Vec::new(),
            consecutive_health_failures: 0,
            probe_count: 0,
            last_probe_unix: None,
        }
    }
}

impl NodeStats {
    /// Record one probe result. The first sample sets the EMA directly;
    /// later samples blend in by alpha.
    pub fn record_probe(&mut self, rtt: Option<Duration>, alpha: f64, now_unix: i64) {
        let sample = if rtt.is_some() { 1.0 } else { 0.0 };
        self.success_ema = if self.probe_count == 0 {
            sample
        } else {
            alpha * sample + (1.0 - alpha) * self.success_ema
        };
        if let Some(rtt) = rtt {
            let ms = rtt.as_secs_f64() * 1000.0;
            self.rtt_ema_ms = Some(match self.rtt_ema_ms {
                None => ms,
                Some(prev) => alpha * ms + (1.0 - alpha) * prev,
            });
            self.recent_rtts_ms.push(ms);
            if self.recent_rtts_ms.len() > RTT_HISTORY {
                self.recent_rtts_ms.remove(0);
            }
        }
        self.probe_count += 1;
        self.last_probe_unix = Some(now_unix);
    }

    pub fn is_probed(&self) -> bool {
        self.probe_count > 0
    }
}

/// Ordering key: success rate descending first, RTT ascending second.
/// Note f64 has no Ord; total_cmp is used here and callers handle the
/// comparison — a standalone compare function reads more clearly.
pub fn score_cmp(a: &NodeStats, b: &NodeStats) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match a.success_ema.total_cmp(&b.success_ema) {
        Ordering::Equal => {}
        ord => return ord,
    }
    // RTT: None (never succeeded) sorts last
    match (a.rtt_ema_ms, b.rtt_ema_ms) {
        (Some(x), Some(y)) => y.total_cmp(&x), // inverted: smaller RTT ranks higher
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

/// Hysteresis decision: does the challenger beat the incumbent by a "clear
/// margin"?
///
/// - A success-rate gap larger than `hysteresis * max(incumbent, 5%)` decides
///   the outcome directly;
/// - Within the hysteresis band, the challenger wins only if its RTT is lower
///   by a `hysteresis` ratio.
pub fn challenger_wins(challenger: &NodeStats, incumbent: &NodeStats, hysteresis: f64) -> bool {
    if !challenger.is_probed() {
        return false;
    }
    if !incumbent.is_probed() {
        return true; // incumbent has no data (e.g. state file lost); any probed challenger may take over
    }
    let margin = hysteresis * incumbent.success_ema.max(0.05);
    let ds = challenger.success_ema - incumbent.success_ema;
    if ds.abs() > margin {
        return ds > 0.0;
    }
    match (challenger.rtt_ema_ms, incumbent.rtt_ema_ms) {
        (Some(c), Some(i)) => c * (1.0 + hysteresis) < i,
        (Some(_), None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHA: f64 = 0.3;

    fn stats(success: f64, rtt_ms: Option<f64>) -> NodeStats {
        NodeStats {
            success_ema: success,
            rtt_ema_ms: rtt_ms,
            recent_rtts_ms: Vec::new(),
            consecutive_health_failures: 0,
            probe_count: 1,
            last_probe_unix: Some(0),
        }
    }

    #[test]
    fn first_sample_sets_ema_directly() {
        let mut s = NodeStats::default();
        s.record_probe(Some(Duration::from_millis(100)), ALPHA, 1);
        assert_eq!(s.success_ema, 1.0);
        assert_eq!(s.rtt_ema_ms, Some(100.0));
        assert_eq!(s.probe_count, 1);
        assert_eq!(s.recent_rtts_ms, vec![100.0]);
    }

    #[test]
    fn rtt_history_is_capped_newest_last() {
        let mut s = NodeStats::default();
        for i in 0..(RTT_HISTORY as u64 + 10) {
            s.record_probe(Some(Duration::from_millis(i)), ALPHA, i as i64);
        }
        assert_eq!(s.recent_rtts_ms.len(), RTT_HISTORY);
        assert_eq!(
            *s.recent_rtts_ms.last().unwrap(),
            (RTT_HISTORY as u64 + 9) as f64
        );
        // Failed probes do not pollute the latency history.
        s.record_probe(None, ALPHA, 999);
        assert_eq!(s.recent_rtts_ms.len(), RTT_HISTORY);
    }

    #[test]
    fn ema_blends_subsequent_samples() {
        let mut s = NodeStats::default();
        s.record_probe(Some(Duration::from_millis(100)), ALPHA, 1);
        s.record_probe(None, ALPHA, 2);
        // success: 0.3*0 + 0.7*1 = 0.7; a failed sample does not change the RTT EMA
        assert!((s.success_ema - 0.7).abs() < 1e-9);
        assert_eq!(s.rtt_ema_ms, Some(100.0));
        s.record_probe(Some(Duration::from_millis(200)), ALPHA, 3);
        // success: 0.3*1 + 0.7*0.7 = 0.79; rtt: 0.3*200 + 0.7*100 = 130
        assert!((s.success_ema - 0.79).abs() < 1e-9);
        assert!((s.rtt_ema_ms.unwrap() - 130.0).abs() < 1e-9);
    }

    #[test]
    fn score_cmp_prefers_success_then_rtt() {
        let a = stats(0.9, Some(300.0));
        let b = stats(0.8, Some(50.0));
        assert_eq!(
            score_cmp(&a, &b),
            std::cmp::Ordering::Greater,
            "success rate outranks RTT"
        );
        let c = stats(0.9, Some(50.0));
        assert_eq!(
            score_cmp(&c, &a),
            std::cmp::Ordering::Greater,
            "equal success rate compares RTT"
        );
    }

    #[test]
    fn challenger_needs_clear_success_margin() {
        let incumbent = stats(0.80, Some(100.0));
        let slightly_better = stats(0.88, Some(100.0)); // +10% < 30% hysteresis
        let clearly_better = stats(0.80 * 1.31, Some(150.0)); // +31% > 30%
        assert!(!challenger_wins(&slightly_better, &incumbent, 0.30));
        assert!(challenger_wins(&clearly_better, &incumbent, 0.30));
        // Clearly worse loses outright
        let worse = stats(0.5, Some(10.0));
        assert!(!challenger_wins(&worse, &incumbent, 0.30));
    }

    #[test]
    fn rtt_tiebreak_within_margin() {
        let incumbent = stats(0.80, Some(100.0));
        // Success rate within the hysteresis band, RTT 50% lower > 30% → wins
        let faster = stats(0.85, Some(50.0));
        assert!(challenger_wins(&faster, &incumbent, 0.30));
        // RTT only 10% lower < 30% → stickiness holds
        let a_bit_faster = stats(0.85, Some(90.0));
        assert!(!challenger_wins(&a_bit_faster, &incumbent, 0.30));
        // RTT slower → holds
        let slower = stats(0.82, Some(200.0));
        assert!(!challenger_wins(&slower, &incumbent, 0.30));
    }

    #[test]
    fn unprobed_nodes_never_challenge() {
        let incumbent = stats(0.1, Some(1000.0));
        assert!(!challenger_wins(&NodeStats::default(), &incumbent, 0.30));
        // When the incumbent has no data, any probed challenger wins outright
        assert!(challenger_wins(
            &stats(0.01, Some(999.0)),
            &NodeStats::default(),
            0.30
        ));
    }

    #[test]
    fn zero_success_incumbent_has_floor_margin() {
        // With incumbent.success_ema = 0 the margin takes the 5% floor, avoiding
        // the "anything >0 wins" flapping
        let incumbent = stats(0.0, None);
        let tiny = stats(0.01, Some(50.0)); // 1% < 5% floor → inside the band → RTT compared (incumbent has no RTT) → wins
        assert!(challenger_wins(&tiny, &incumbent, 0.30));
    }
}
