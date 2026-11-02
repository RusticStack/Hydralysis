//! The sampling policy of a trace session (port of the JS policy in `runtime_agents.py`).
//!
//! Every hit is counted per site in the hook (`hits`, and `kept` = took a ring sequence number); a hit the policy
//! skips costs a counter and a test, and is reported exactly (`hits - kept`). `adaptive` (the default) keeps every hit
//! while the offered rate fits the budget and, when it does not, thins the busiest sites by a power-of-two stride so the
//! kept records fit; a site that fits under its fair share stays exact. `exact` never thins (a full ring still drops,
//! counted); `fixed` keeps one hit in `stride`. Ring drops halve the effective budget; calm periods win it back.
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub const DEFAULT_RATE_BUDGET: f64 = 120_000.0;
const MAX_STRIDE: u32 = 65_536;

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Adaptive,
    Exact,
    Fixed(u32),
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    /// Kept records per second, all sites together, before the adaptive policy thins.
    pub rate_budget: f64,
    pub interval: Duration,
    /// Sites that are never thinned.
    pub exact_sites: HashSet<usize>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            mode: Mode::Adaptive,
            rate_budget: DEFAULT_RATE_BUDGET,
            interval: Duration::from_millis(25),
            exact_sites: HashSet::new(),
        }
    }
}

fn pow2_ge(x: f64) -> u32 {
    let mut p = 1u32;
    while (p as f64) < x && p < MAX_STRIDE {
        p *= 2;
    }
    p
}

#[derive(Debug)]
pub struct Sampler {
    pub policy: Policy,
    sites: usize,
    t0: Option<Instant>,
    last_t: Option<Instant>,
    last_hits: Vec<u64>,
    last_drops: u64,
    rate: Vec<Option<f64>>,
    stride: Vec<u32>,
    thinned: Vec<bool>,
    pub effective: f64,
    pub changes: u32,
}

impl Sampler {
    pub fn new(policy: Policy, sites: usize) -> Sampler {
        let effective = policy.rate_budget;
        Sampler {
            policy,
            sites,
            t0: None,
            last_t: None,
            last_hits: vec![0; sites],
            last_drops: 0,
            rate: vec![None; sites],
            stride: vec![1; sites],
            thinned: vec![false; sites],
            effective,
            changes: 0,
        }
    }

    pub fn stride(&self, site: usize) -> u32 {
        self.stride[site]
    }

    /// A site's `skipped` count as reported: only a site that was ever thinned can have skipped a hit (this keeps
    /// exact mode from reporting a phantom skip for a hit that was counted but not yet kept when the counters were read).
    pub fn reported_skipped(&self, site: usize, hits: u64, kept: u64) -> u64 {
        if self.thinned[site] {
            hits.saturating_sub(kept)
        } else {
            0
        }
    }

    fn apply(&mut self, site: usize, stride: u32, out: &mut Vec<(usize, u32)>) {
        if self.stride[site] != stride {
            self.stride[site] = stride;
            if stride > 1 {
                self.thinned[site] = true;
            }
            self.changes += 1;
            out.push((site, stride));
        }
    }

    /// One policy step. `hits` are the cumulative hit counts per site, `dropped` the cumulative ring drops. Returns the
    /// strides to set (only changes).
    pub fn step(&mut self, now: Instant, hits: &[u64], dropped: u64) -> Vec<(usize, u32)> {
        let mut out = Vec::new();
        let t0 = *self.t0.get_or_insert(now);
        match self.policy.mode {
            Mode::Exact => return out,
            Mode::Fixed(n) => {
                let s = pow2_ge(n as f64);
                for site in 0..self.sites {
                    let want = if self.policy.exact_sites.contains(&site) {
                        1
                    } else {
                        s
                    };
                    self.apply(site, want, &mut out);
                }
                return out;
            }
            Mode::Adaptive => {}
        }
        let Some(last) = self.last_t else {
            self.last_t = Some(now);
            self.last_hits = hits.to_vec();
            return out;
        };
        let dt = now.duration_since(last).as_secs_f64();
        // The first moments decide whether a hot site fills a ring before the policy has seen it: look sooner then.
        let wait = if now.duration_since(t0) < Duration::from_millis(500) {
            0.005
        } else {
            self.policy.interval.as_secs_f64()
        };
        if dt < wait {
            return out;
        }
        let dd = dropped.saturating_sub(self.last_drops);
        self.last_drops = dropped;
        self.last_t = Some(now);
        for (site, &h) in hits.iter().enumerate().take(self.sites) {
            let r = (h.saturating_sub(self.last_hits[site])) as f64 / dt;
            self.rate[site] = Some(self.rate[site].map_or(r, |old| 0.5 * old + 0.5 * r));
        }
        self.last_hits = hits.to_vec();
        if dd > 0 {
            self.effective = (self.policy.rate_budget / 16.0).max(self.effective / 2.0);
        } else {
            self.effective = self.policy.rate_budget.min(self.effective * 1.25);
        }
        // Water-filling: sites that fit under the fair share stay exact, the rest share what is left.
        let mut left = self.effective;
        let mut open: Vec<usize> = Vec::new();
        for site in 0..self.sites {
            if self.policy.exact_sites.contains(&site) {
                left -= self.rate[site].unwrap_or(0.0);
            } else if self.rate[site].unwrap_or(0.0) > 0.0 || self.stride[site] > 1 {
                open.push(site);
            }
        }
        open.sort_by(|a, b| self.rate[*a].partial_cmp(&self.rate[*b]).unwrap());
        left = left.max(self.effective * 0.1);
        let n = open.len();
        for (i, site) in open.into_iter().enumerate() {
            let share = left / (n - i) as f64;
            let r = self.rate[site].unwrap_or(0.0);
            if r <= share {
                left -= r;
                self.apply(site, 1, &mut out);
            } else {
                let stride = pow2_ge((r / share).ceil());
                self.apply(site, stride, &mut out);
                left -= r / stride as f64;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(
        s: &mut Sampler,
        t: Instant,
        secs: f64,
        hits: &[u64],
        dropped: u64,
    ) -> Vec<(usize, u32)> {
        s.step(t + Duration::from_secs_f64(secs), hits, dropped)
    }

    #[test]
    fn under_budget_stays_exact() {
        let mut s = Sampler::new(Policy::default(), 2);
        let t = Instant::now();
        assert!(feed(&mut s, t, 0.0, &[0, 0], 0).is_empty());
        assert!(feed(&mut s, t, 0.1, &[1000, 500], 0).is_empty()); // 10k/s and 5k/s, budget 120k/s
        assert_eq!((s.stride(0), s.stride(1)), (1, 1));
        assert_eq!(
            s.reported_skipped(0, 10, 7),
            0,
            "never thinned: no phantom skip"
        );
    }

    #[test]
    fn the_busiest_site_is_thinned_and_the_fair_one_stays_exact() {
        let mut s = Sampler::new(Policy::default(), 2);
        let t = Instant::now();
        feed(&mut s, t, 0.0, &[0, 0], 0);
        // site 0: 1.2M hits/s, site 1: 10k hits/s, budget 120k/s
        let ch = feed(&mut s, t, 1.0, &[1_200_000, 10_000], 0);
        assert_eq!(
            ch,
            vec![(0, 16)],
            "stride is a power of two covering rate/share"
        );
        assert_eq!(s.stride(1), 1);
        assert_eq!(s.reported_skipped(0, 100, 70), 30);
    }

    #[test]
    fn drops_halve_the_budget_and_calm_wins_it_back() {
        let mut s = Sampler::new(Policy::default(), 1);
        let t = Instant::now();
        feed(&mut s, t, 0.0, &[0], 0);
        feed(&mut s, t, 1.0, &[100_000], 5);
        assert_eq!(s.effective, DEFAULT_RATE_BUDGET / 2.0);
        feed(&mut s, t, 2.0, &[200_000], 5);
        assert_eq!(s.effective, DEFAULT_RATE_BUDGET / 2.0 * 1.25);
    }

    #[test]
    fn fixed_and_exact_modes() {
        let mut f = Sampler::new(
            Policy {
                mode: Mode::Fixed(5),
                exact_sites: [1].into(),
                ..Policy::default()
            },
            2,
        );
        assert_eq!(f.step(Instant::now(), &[0, 0], 0), vec![(0, 8)]);
        let mut e = Sampler::new(
            Policy {
                mode: Mode::Exact,
                ..Policy::default()
            },
            2,
        );
        assert!(e.step(Instant::now(), &[9, 9], 0).is_empty());
    }
}
