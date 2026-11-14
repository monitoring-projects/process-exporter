package diagnose

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Monitoring-Projects/process-exporter/proc"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type gen struct {
	rssAnon, vmData, fds, threads func(t time.Duration) float64
	cpuRate                       func(t time.Duration) float64 // cores
	blocked                       bool
	volRate                       float64
	restartAt                     []time.Duration
}

const mib = 1 << 20

func run(t *testing.T, g gen, span time.Duration, cfg Config) (*Engine, time.Time) {
	t.Helper()
	cfg.MemAvailable = func() float64 { return 40 * 1024 * mib }
	e := New(cfg, regexp.MustCompile(".+"))
	t0 := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	step := 30 * time.Second
	var cpu, vol float64
	start := t0.Add(-time.Hour)
	for el := time.Duration(0); el <= span; el += step {
		for _, r := range g.restartAt {
			if el == r {
				start = t0.Add(el)
				cpu = 0
			}
		}
		cores := 0.3
		if g.cpuRate != nil {
			cores = g.cpuRate(el)
		}
		cpu += cores * step.Seconds()
		vol += g.volRate * step.Seconds()
		f := func(fn func(time.Duration) float64, d float64) float64 {
			if fn == nil {
				return d
			}
			return fn(el)
		}
		grp := proc.Group{
			Procs:           1,
			OldestStartTime: start,
			Memory:          proc.Memory{ResidentBytes: uint64(f(g.rssAnon, 100*mib)), VirtualBytes: uint64(f(g.vmData, 500*mib))},
			OpenFDs:         uint64(f(g.fds, 20)),
			NumThreads:      uint64(f(g.threads, 10)),
			States:          proc.States{Running: 1, Sleeping: 2},
		}
		grp.CPUUserTime = cpu
		grp.CtxSwitchVoluntary = uint64(vol)
		if g.blocked {
			grp.States.Waiting = 1
			grp.Wchans = map[string]int{"io_schedule": 1}
		}
		ex := proc.GroupExtra{
			Ext: proc.MemoryExt{RssAnonBytes: uint64(f(g.rssAnon, 100*mib)), VmDataBytes: uint64(f(g.vmData, 500*mib))}, FDLimitMin: 1024,
		}
		e.Observe(t0.Add(el), proc.GroupByName{"svc": grp}, map[string]proc.GroupExtra{"svc": ex}, nil)
	}
	return e, t0.Add(span)
}

func saw(base, amp float64, period time.Duration) func(time.Duration) float64 {
	return func(t time.Duration) float64 {
		ph := float64(t%period) / float64(period)
		return base + amp*ph
	}
}

func findings(e *Engine, now time.Time) map[string]*Finding {
	m := map[string]*Finding{}
	for _, f := range e.Flagged(now)["svc"] {
		m[f.Symptom] = f
	}
	return m
}

func TestMemoryLeakUnderSawtooth(t *testing.T) {
	// 30 MiB/h floor growth hidden under a 600 MiB sawtooth with a 3 min period.
	span := 8 * time.Hour
	g := gen{rssAnon: func(el time.Duration) float64 {
		return 500*mib + 30*mib*el.Hours() + saw(0, 600*mib, 3*time.Minute)(el)
	}}
	e, now := run(t, g, span, Config{})
	f := findings(e, now)["memory_leak_suspected"]
	if f == nil {
		t.Fatalf("leak not detected: %v", e.Flagged(now))
	}
	if got := f.Evidence["slope_bytes_per_hour"] / mib; math.Abs(got-30) > 5 {
		t.Errorf("slope %.1f MiB/h, want ~30", got)
	}
	if f.ETA <= 0 || f.ETAResource != "memory" {
		t.Errorf("no ETA: %+v", f)
	}
}

func TestHealthySawtoothNoSymptom(t *testing.T) {
	g := gen{rssAnon: saw(500*mib, 600*mib, 3*time.Minute)}
	e, now := run(t, g, 8*time.Hour, Config{})
	if fl := e.Flagged(now); len(fl) != 0 {
		t.Fatalf("healthy workload flagged: %v", fl["svc"][0])
	}
}

func TestLeakFollowsWork(t *testing.T) {
	// Work arrives in bursts; the floor grows only with the work done.
	cpu := func(el time.Duration) float64 {
		if int(el.Minutes()/20)%2 == 0 {
			return 2
		}
		return 0.1
	}
	var acc float64
	last := time.Duration(0)
	rss := func(el time.Duration) float64 {
		for ; last < el; last += 30 * time.Second {
			acc += cpu(last) * 30 * 0.2 * mib // 0.2 MiB per CPU second
		}
		return 300*mib + acc
	}
	e, now := run(t, gen{rssAnon: rss, cpuRate: cpu}, 8*time.Hour, Config{})
	f := findings(e, now)["memory_leak_suspected"]
	if f == nil {
		t.Fatalf("not detected: %v", e.Flagged(now))
	}
	if f.Driver != "work" {
		t.Errorf("driver %q, want work (corr %v)", f.Driver, e.state["svc"].lastEval.Corr)
	}
	if got := e.state["svc"].lastEval.BytesPerCPUSecond / mib; math.Abs(got-0.2) > 0.05 {
		t.Errorf("bytes per cpu second %.3f MiB, want 0.2", got)
	}
}

func TestAddressSpaceLeakWithoutRSS(t *testing.T) {
	g := gen{vmData: func(el time.Duration) float64 { return 2048*mib + 5120*mib*el.Hours() }}
	e, now := run(t, g, 6*time.Hour, Config{})
	f := findings(e, now)
	if f["address_space_leak"] == nil {
		t.Fatalf("address space leak not detected: %v", e.Flagged(now))
	}
	if f["memory_leak_suspected"] != nil {
		t.Errorf("memory leak flagged with flat RSS")
	}
}

func TestFDLeakETA(t *testing.T) {
	g := gen{fds: func(el time.Duration) float64 { return 100 + 20*el.Hours() }}
	e, now := run(t, g, 6*time.Hour, Config{})
	f := findings(e, now)["fd_leak"]
	if f == nil {
		t.Fatalf("fd leak not detected")
	}
	if f.ETAResource != "fd" || f.ETA <= 0 {
		t.Fatalf("missing fd ETA: %+v", f)
	}
	if want := (1024 - 220.0) / 20; math.Abs(f.ETA.Hours()-want) > 3 {
		t.Errorf("eta %.1fh want ~%.1fh", f.ETA.Hours(), want)
	}
}

func TestBusyLoop(t *testing.T) {
	g := gen{cpuRate: func(time.Duration) float64 { return 1.0 }, volRate: 3}
	e, now := run(t, g, 20*time.Minute, Config{})
	if findings(e, now)["cpu_busy_loop"] == nil {
		t.Fatalf("busy loop not detected: %v", e.Flagged(now))
	}
}

func TestBusyButWorkingIsNotALoop(t *testing.T) {
	g := gen{cpuRate: func(el time.Duration) float64 {
		if int(el.Seconds()/90)%2 == 0 {
			return 3
		}
		return 0.2
	}, volRate: 5000}
	e, now := run(t, g, 20*time.Minute, Config{})
	if findings(e, now)["cpu_busy_loop"] != nil {
		t.Fatalf("bursty worker flagged as busy loop")
	}
}

func TestBlockedIO(t *testing.T) {
	e, now := run(t, gen{blocked: true}, 20*time.Minute, Config{})
	f := findings(e, now)["blocked_io"]
	if f == nil || f.Detail != "io_schedule" {
		t.Fatalf("blocked io not detected: %+v", f)
	}
}

func TestRestartLoop(t *testing.T) {
	g := gen{restartAt: []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}}
	e, now := run(t, g, 4*time.Hour, Config{})
	if findings(e, now)["restart_loop"] == nil {
		t.Fatalf("restart loop not detected, restarts=%d", len(e.state["svc"].restarts))
	}
}

func TestHoldKeepsSymptomThenExpires(t *testing.T) {
	e, now := run(t, gen{blocked: true}, 20*time.Minute, Config{})
	if findings(e, now.Add(5*time.Minute)) == nil || len(e.Flagged(now.Add(5*time.Minute))) == 0 {
		t.Fatalf("symptom dropped inside hold time")
	}
	if len(e.Flagged(now.Add(30*time.Minute))) != 0 {
		t.Fatalf("symptom not expired after hold time")
	}
}

func collectAll(e *Engine) []*dto.Metric {
	ch := make(chan prometheus.Metric, 1000)
	e.Collect(ch)
	close(ch)
	var out []*dto.Metric
	for m := range ch {
		d := &dto.Metric{}
		_ = m.Write(d)
		out = append(out, d)
	}
	return out
}

func TestHealthyGroupEmitsNoPerGroupSeries(t *testing.T) {
	e, _ := run(t, gen{}, 2*time.Hour, Config{})
	for _, m := range collectAll(e) {
		for _, l := range m.Label {
			if l.GetName() == "groupname" {
				t.Fatalf("healthy group emitted a per-group series: %v", m)
			}
		}
	}
}

func TestDetailGroupAlwaysEmitsDetails(t *testing.T) {
	cfg := Config{DetailAlways: func(n string) bool { return n == "svc" }}
	e, _ := run(t, gen{}, 2*time.Hour, cfg)
	var n int
	for _, m := range collectAll(e) {
		for _, l := range m.Label {
			if l.GetName() == "groupname" && l.GetValue() == "svc" {
				n++
				break
			}
		}
	}
	if n < 10 {
		t.Fatalf("detail group emitted only %d series", n)
	}
}

func TestVerdictLabelsAreStable(t *testing.T) {
	g := gen{fds: func(el time.Duration) float64 { return 100 + 20*el.Hours() }}
	e, _ := run(t, g, 6*time.Hour, Config{})
	var v *dto.Metric
	for _, m := range collectAll(e) {
		for _, l := range m.Label {
			if l.GetName() == "verdict" && l.GetValue() == "fd_leak" {
				v = m
			}
		}
	}
	if v == nil {
		t.Fatal("no verdict series")
	}
	var ev string
	for _, l := range v.Label {
		if l.GetName() == "evidence" {
			ev = l.GetValue()
		}
	}
	if !strings.Contains(ev, "slope_per_hour=20") {
		t.Errorf("evidence label %q lacks rounded slope", ev)
	}
}

func TestShortLivedChurnIsNotARestartLoop(t *testing.T) {
	e := New(Config{}, regexp.MustCompile(".+"))
	t0 := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 400; i++ {
		now := t0.Add(time.Duration(i) * 5 * time.Second)
		// a new 5 s lived process every sample, as a shell loop running sleep
		grp := proc.Group{Procs: 1, OldestStartTime: now}
		e.Observe(now, proc.GroupByName{"sleep": grp}, nil, nil)
		e.Observe(now.Add(3*time.Second), proc.GroupByName{"sleep": proc.Group{}}, nil, nil)
	}
	if fl := e.Flagged(t0.Add(40 * time.Minute)); len(fl) != 0 {
		t.Fatalf("short-lived churn flagged: %v", fl["sleep"][0])
	}
}
