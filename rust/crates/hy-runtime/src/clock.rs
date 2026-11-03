//! Timestamp calibration: the agent stamps records with `rdtsc` (or QueryPerformanceCounter when the CPU has no
//! invariant TSC). The agent samples both clocks once at init; the host refines the TSC-to-QPC ratio from the whole
//! interval since then, on every drain, as the CModule recorder did.

#[derive(Clone, Copy, Debug)]
pub struct Clock {
    pub use_qpc: bool,
    pub tsc0: u64,
    pub qpc0: u64,
    pub freq: u64,
    /// QPC ticks per TSC tick.
    pub ratio: f64,
}

impl Clock {
    pub fn new(use_qpc: bool, tsc0: u64, qpc0: u64, freq: u64) -> Clock {
        Clock {
            use_qpc,
            tsc0,
            qpc0,
            freq,
            ratio: 0.0,
        }
    }

    /// Refine the ratio from a fresh `(tsc, qpc)` pair taken on the host (the TSC is machine-wide).
    pub fn refine(&mut self, tsc_now: u64, qpc_now: u64) {
        if self.use_qpc {
            self.ratio = 1.0;
            return;
        }
        let dt = tsc_now.saturating_sub(self.tsc0);
        let dq = qpc_now.saturating_sub(self.qpc0);
        // Under ~1 ms the quotient is dominated by sampling jitter: keep the previous estimate.
        if dt > 1_000_000 && dq > 1000 {
            self.ratio = dq as f64 / dt as f64;
        }
    }

    /// A span of record-clock ticks in QueryPerformanceCounter ticks.
    pub fn span_to_qpc(&self, ticks: u64) -> u64 {
        if self.use_qpc {
            ticks
        } else {
            (ticks as f64 * self.ratio) as u64
        }
    }

    /// A record timestamp in QueryPerformanceCounter ticks. Zero before the first usable refinement.
    pub fn to_qpc(&self, t: u64) -> u64 {
        if self.use_qpc {
            return t;
        }
        if self.ratio == 0.0 {
            return 0;
        }
        let d = t as i128 - self.tsc0 as i128;
        (self.qpc0 as i128 + (d as f64 * self.ratio) as i128).max(0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsc_conversion() {
        let mut c = Clock::new(false, 1_000_000, 500, 10_000_000);
        assert_eq!(c.to_qpc(1_000_100), 0);
        c.refine(1_000_000 + 3_000_000, 500 + 10_000); // 3 TSC ticks per QPC tick... ratio 1/300
        let q = c.to_qpc(1_000_000 + 1_500_000);
        assert!((q as i64 - 5_500).abs() <= 1, "{q}");
    }

    #[test]
    fn spans_convert_without_an_origin() {
        let mut c = Clock::new(false, 0, 0, 10_000_000);
        assert_eq!(c.span_to_qpc(3000), 0, "no usable ratio yet");
        c.refine(3_000_000, 10_000);
        assert_eq!(c.span_to_qpc(300_000), 1000);
        assert_eq!(Clock::new(true, 0, 0, 1).span_to_qpc(77), 77);
    }

    #[test]
    fn qpc_passthrough() {
        let mut c = Clock::new(true, 0, 0, 10_000_000);
        c.refine(5, 5);
        assert_eq!(c.to_qpc(1234), 1234);
    }
}
