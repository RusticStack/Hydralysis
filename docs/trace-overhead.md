# Trace recorder overhead

Measured by `benchmarks/trace_overhead.py` on the real `frameloop` fixture (x64): capture off against capture on with the
declared baseline profile (nine frameloop hooks, about 10 probe hits per frame) and the **default** recorder settings
(32 rings of 1 MiB, 10 ms batches, 20 ms backpressure budget, 16-batch acknowledgement window). Rounds are interleaved
(off, on, off, on, ...), five per workload; the fixture times its own frames with QueryPerformanceCounter. Figures are medians
over the five rounds, taken on a shared machine that other builds were using at the same time. Results:
`E:/Projects/Hydra/_logs/trace-lcap2/overhead/overhead-final2.json` (all three workloads) and `overhead-final3.json`
(tight and paced, after the shedding change below).

| Workload | frame p50 off -> on | mean off -> on | mean overhead | p99 overhead | hits dropped | notes |
| --- | --- | --- | --- | --- | --- | --- |
| frame16 (16 ms of work per frame, 600 frames) | 16015 -> 16030 us | 16043 -> 16061 us | 0.1% | 0.2% | 0 | 533 hits/s |
| paced (200 us of work per frame, 20000 frames) | 204.3 -> 207.9 us | 205.3 -> 208.9 us | 1.7% | 3.6% | 0 in 5 rounds | 34.8k hits/s, worker CPU share 0.26 |
| tight (bare loop, about 4 us per frame, 20000 frames) | 4.2 -> 6.8 us | 4.2 -> 8.7 us | 113% | 91% | 678k of 990k, all counted and cited | 117k hits/s accepted |

Reading the numbers:

* A frame that does work is within the 5% target (0.1% at 60 Hz, 1.7% with 200 us frames). The in-frame cost of a hook is about
  0.3 us a hit (p50 +3.6 us for 9.9 hits in the paced loop).
* The bare loop produces about 2 million hits a second. The writer (decode, redact, hash chain, JSON, disk) sustains about
  60 to 120 thousand records a second, so the recorder cannot keep every record of a loop that tight. It does not stall the
  target for long: a hook waits at most `bp_ms` (20 ms) for the drain, then the ring sheds (drops at once, counted) until the drain
  has freed half of it, so the worst hitch is one budget, not one budget per hit. Every dropped record is counted per ring and
  cited by a `core.capture.gap` event; the segment verifies clean. Before the shedding change the same loop ran the target 24 times
  slower on average (mean frame 4.98 -> 90.7 us), and one paced round under machine load dropped 75 records with a 180 ms frame.
* First-use cost: probes are installed before the first frame (install time per probe is in the result file, `install_ms`); the
  mean of the first ten frames is recorded in `first10_mean_us`.
* A 0.0 ms install time means the timer's resolution (1 ms `Date.now`) was too coarse, not that installing was free.
* Not established: that these ratios hold for a game other than this fixture; the hook cost depends on how many threads hit
  probes and how deep the stack walk is (the baseline hooks use stack depth 1 to 4).
