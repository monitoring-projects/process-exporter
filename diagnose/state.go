// Package diagnose samples selected process groups over time, correlates the
// signals and derives symptoms (leak, spin, stuck IO, ...) and predictions, so
// that only a handful of derived series have to be stored instead of every raw
// per-process metric.
package diagnose

import (
	"time"
)

// Config holds the thresholds of the analysis. Zero values are replaced by
// defaults in New.
type Config struct {
	// Window is the fine sample window used for rates (busy loop, faults).
	Window time.Duration
	// FloorSpan is how long the per-bucket floors are kept for trend fits.
	FloorSpan time.Duration
	// Bucket is the floor bucket size; the minimum of each signal in a bucket
	// is kept, which removes per-cycle sawtooth.
	Bucket time.Duration
	// MinSpan is the minimum observed span before a trend can be reported.
	MinSpan time.Duration
	// Hold keeps a symptom active after it was last detected (anti-flap).
	Hold time.Duration
	// RateWindow is the window for busy loop / fault / D-state detection.
	RateWindow time.Duration

	R2Min                   float64
	LeakMinBytesPerHour     float64
	VMGrowthMinBytesPerHour float64
	VMToRSSRatio            float64
	FDMinPerHour            float64
	ThreadMinPerHour        float64
	SwapMinBytesPerHour     float64

	BusyLoopCores     float64
	BusyLoopMaxCV     float64
	BusyLoopMaxVolCtx float64
	NonvolCtxPerSec   float64
	MinorFaultsPerSec float64
	MajorFaultsPerSec float64
	BlockedShare      float64
	ZombieMinAge      time.Duration
	// MinLife is how long an incarnation must have lived for its end to count
	// as a restart; shorter lives are normal churn of short-lived commands.
	MinLife            time.Duration
	RestartLoopCount   int
	MapsNearLimitRatio float64
	MaxMapCount        float64
	MemAvailable       func() float64
	MaxGroups          int
	// cgroup based thresholds
	ThrottleRatio, MemPSISome, MemPSIFull, IOPSISome, IOPSIFull float64
	CgroupNearLimit, PidsNearLimit                              float64
	DetailAlways                                                func(group string) bool
}

func (c *Config) defaults() {
	d := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	f := func(p *float64, v float64) {
		if *p == 0 {
			*p = v
		}
	}
	d(&c.Window, 30*time.Minute)
	d(&c.FloorSpan, 6*time.Hour)
	d(&c.Bucket, 5*time.Minute)
	d(&c.MinSpan, 2*time.Hour)
	d(&c.Hold, 10*time.Minute)
	d(&c.RateWindow, 5*time.Minute)
	d(&c.ZombieMinAge, 10*time.Minute)
	d(&c.MinLife, 30*time.Second)
	f(&c.R2Min, 0.8)
	f(&c.LeakMinBytesPerHour, 5<<20)
	f(&c.VMGrowthMinBytesPerHour, 512<<20)
	f(&c.VMToRSSRatio, 50)
	f(&c.FDMinPerHour, 5)
	f(&c.ThreadMinPerHour, 2)
	f(&c.SwapMinBytesPerHour, 1<<20)
	f(&c.BusyLoopCores, 0.9)
	f(&c.BusyLoopMaxCV, 0.15)
	f(&c.BusyLoopMaxVolCtx, 100)
	f(&c.NonvolCtxPerSec, 2000)
	f(&c.MinorFaultsPerSec, 100000)
	f(&c.MajorFaultsPerSec, 20)
	f(&c.BlockedShare, 0.8)
	f(&c.MapsNearLimitRatio, 0.8)
	f(&c.ThrottleRatio, 0.25)
	f(&c.MemPSISome, 0.10)
	f(&c.MemPSIFull, 0.02)
	f(&c.IOPSISome, 0.20)
	f(&c.IOPSIFull, 0.05)
	f(&c.CgroupNearLimit, 0.90)
	f(&c.PidsNearLimit, 0.80)
	if c.RestartLoopCount == 0 {
		c.RestartLoopCount = 3
	}
	if c.MaxGroups == 0 {
		c.MaxGroups = 2000
	}
}

// Sample is one observation of a group.
type Sample struct {
	T     time.Time
	Procs int

	RssAnon, Rss, RssFile, RssShmem float64
	VmData, Virtual, VmHWM, VmPTE   float64
	VmLck, Swap                     float64
	FDs, FDLimit, Threads           float64
	MapCount                        float64

	// Cumulative counters (never decrease at group level).
	CPU, CtxVol, CtxNonvol, MinFlt, MajFlt, IOBytes float64

	Running, Sleeping, Blocked, Zombie int

	// cgroup data (HasCg false when not collected)
	HasCg                                  bool
	CgNonReclaim, CgLimit, CgFile, CgUsage float64
	CgPeriods, CgThrottled, CgOOMKills     float64
	CgThrottledSec                         float64
	CgPSIMemSome, CgPSIMemFull             float64
	CgPSIIOSome, CgPSIIOFull               float64
	CgPSIMem, CgPSIIO                      bool
	CgPidsCur, CgPidsMax                   float64
	CgCPULimit                             float64
	TopWchan                               string
	Start                                  int64
}

// anon returns the anonymous resident size, falling back to RSS when the
// status breakdown is unavailable.
func (s Sample) anon() float64 {
	if s.RssAnon > 0 {
		return s.RssAnon
	}
	return s.Rss
}

func (s Sample) vm() float64 {
	if s.VmData > 0 {
		return s.VmData
	}
	return s.Virtual
}

// bucket keeps the floor (minimum) of each signal for one time slice.
type bucket struct {
	start                                  time.Time
	n                                      int
	minAnon, minVm, minFD, minThr, minSwap float64
	minProcs, maxProcs                     int
	cpuEnd, ctxEnd                         float64
	lastT                                  time.Time
}

func (b *bucket) add(s Sample) {
	if b.n == 0 {
		*b = bucket{start: b.start, minAnon: s.anon(), minVm: s.vm(), minFD: s.FDs, minThr: s.Threads,
			minSwap: s.Swap, minProcs: s.Procs, maxProcs: s.Procs}
	} else {
		b.minAnon = minf(b.minAnon, s.anon())
		b.minVm = minf(b.minVm, s.vm())
		b.minFD = minf(b.minFD, s.FDs)
		b.minThr = minf(b.minThr, s.Threads)
		b.minSwap = minf(b.minSwap, s.Swap)
		if s.Procs < b.minProcs {
			b.minProcs = s.Procs
		}
		if s.Procs > b.maxProcs {
			b.maxProcs = s.Procs
		}
	}
	b.n++
	b.cpuEnd = s.CPU
	b.ctxEnd = s.CtxVol + s.CtxNonvol
	b.lastT = s.T
}

func minf(a, b float64) float64 {
	if b < a {
		return b
	}
	return a
}

// groupState is the history of one analysed group.
type groupState struct {
	fine     []Sample
	buckets  []bucket
	restarts []time.Time
	incStart time.Time
	lastSeen time.Time
	lastWarn map[string]time.Time

	active   map[string]*Finding
	lastEval Evaluation
	evidence map[string]evidenceText
}

type evidenceText struct {
	text string
	at   time.Time
}

func (g *groupState) add(s Sample, cfg *Config) {
	// Restart: a new oldest-start time or the group coming back from empty.
	// Incarnations that lived less than MinLife are churn, not restarts.
	if n := len(g.fine); n > 0 {
		prev := g.fine[n-1]
		restarted := false
		if prev.Procs > 0 && s.Procs > 0 && s.Start != 0 && prev.Start != 0 && s.Start > prev.Start+1 {
			restarted = true
		} else if prev.Procs == 0 && s.Procs > 0 {
			restarted = true
		}
		if restarted {
			if !g.incStart.IsZero() && prev.T.Sub(g.incStart) >= cfg.MinLife {
				g.restarts = append(g.restarts, s.T)
			}
			g.fine, g.buckets = nil, nil
			g.incStart = s.T
		}
	}
	if g.incStart.IsZero() && s.Procs > 0 {
		g.incStart = s.T
	}
	// Drop restarts older than the floor span.
	for len(g.restarts) > 0 && s.T.Sub(g.restarts[0]) > cfg.FloorSpan {
		g.restarts = g.restarts[1:]
	}

	g.fine = append(g.fine, s)
	for len(g.fine) > 1 && s.T.Sub(g.fine[0].T) > cfg.Window {
		g.fine = g.fine[1:]
	}

	bs := s.T.Truncate(cfg.Bucket)
	if n := len(g.buckets); n == 0 || !g.buckets[n-1].start.Equal(bs) {
		g.buckets = append(g.buckets, bucket{start: bs})
	}
	g.buckets[len(g.buckets)-1].add(s)
	for len(g.buckets) > 1 && s.T.Sub(g.buckets[0].start) > cfg.FloorSpan {
		g.buckets = g.buckets[1:]
	}
	g.lastSeen = s.T
}

// full returns buckets whose slice is complete (all but the newest), which
// avoids the partial-bucket bias on the floor.
func (g *groupState) full() []bucket {
	if len(g.buckets) < 2 {
		return nil
	}
	return g.buckets[:len(g.buckets)-1]
}
