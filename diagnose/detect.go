package diagnose

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Symptom names (stable: used in alerts and dashboards).
const (
	SymMemoryLeak       = "memory_leak_suspected"
	SymAddressSpaceLeak = "address_space_leak"
	SymFDLeak           = "fd_leak"
	SymThreadLeak       = "thread_leak"
	SymSwapping         = "swapping"
	SymCPUBusyLoop      = "cpu_busy_loop"
	SymSchedContention  = "scheduler_contention"
	SymMinorFaultStorm  = "minor_fault_storm"
	SymMajorFaultPress  = "major_fault_pressure"
	SymBlockedIO        = "blocked_io"
	SymZombies          = "zombie_accumulation"
	SymRestartLoop      = "restart_loop"
	SymMapsNearLimit    = "maps_near_limit"
)

// Finding is one detected symptom with the data that supports it.
type Finding struct {
	Symptom    string
	Severity   string // info, warning, critical
	Confidence float64
	// Driver says what the growth follows: work (per processing cycle), time,
	// or unknown. Empty for non-trend symptoms.
	Driver   string
	Evidence map[string]float64
	// ETA is the predicted time until the resource is exhausted, 0 if unknown.
	ETA         time.Duration
	ETAResource string
	// Detail is a short free label, for example the dominant wchan.
	Detail string
}

// Trend is a fitted slope of a bucket floor.
type Trend struct {
	PerHour float64
	R2      float64
}

// Evaluation is the full result of analysing one group at one time.
type Evaluation struct {
	Findings []*Finding
	Trends   map[string]Trend
	Rates    map[string]float64
	Corr     map[string]float64
	Sawtooth float64
	Observed time.Duration
	Restarts int
	Latest   Sample
	// BytesPerCPUSecond is the memory floor growth per CPU second of work.
	BytesPerCPUSecond float64
}

// sustained reports whether the second half of the floor series still grows at
// least half as fast as the whole series. It rejects the startup ramp of a
// process that fills its caches and then plateaus, which a single linear fit
// over the whole span would report as a leak.
func sustained(bs []bucket, sel func(bucket) float64, whole fit) bool {
	h := bs[len(bs)/2:]
	if len(h) < 4 {
		return false
	}
	f, _ := trendOf(h, sel)
	return f.Slope >= 0.5*whole.Slope
}

func hours(t time.Time, t0 time.Time) float64 { return t.Sub(t0).Hours() }

func trendOf(bs []bucket, sel func(bucket) float64) (fit, []float64) {
	xs := make([]float64, len(bs))
	ys := make([]float64, len(bs))
	for i, b := range bs {
		xs[i] = hours(b.start, bs[0].start)
		ys[i] = sel(b)
	}
	return linfit(xs, ys), ys
}

// evaluate analyses a group. It is pure: it only reads the group state.
func evaluate(g *groupState, cfg *Config, now time.Time) Evaluation {
	ev := Evaluation{
		Trends: map[string]Trend{},
		Rates:  map[string]float64{},
		Corr:   map[string]float64{},
	}
	if len(g.fine) == 0 {
		return ev
	}
	ev.Latest = g.fine[len(g.fine)-1]
	ev.Restarts = len(g.restarts)

	if len(g.restarts) >= cfg.RestartLoopCount {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymRestartLoop, Severity: "critical", Confidence: 1,
			Evidence: map[string]float64{"restarts_in_floor_span": float64(len(g.restarts))}})
	}

	full := g.full()
	if len(full) > 0 {
		ev.Observed = full[len(full)-1].start.Sub(full[0].start) + cfg.Bucket
	}
	g.trends(&ev, full, cfg)
	g.rates(&ev, cfg)
	g.sawtooth(&ev)

	l := ev.Latest
	if cfg.MaxMapCount > 0 && l.MapCount > 0 && l.MapCount/cfg.MaxMapCount >= cfg.MapsNearLimitRatio {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymMapsNearLimit, Severity: "critical", Confidence: 1,
			Evidence: map[string]float64{"map_count": l.MapCount, "max_map_count": cfg.MaxMapCount}})
	}
	sort.Slice(ev.Findings, func(i, j int) bool { return sevRank(ev.Findings[i]) > sevRank(ev.Findings[j]) })
	return ev
}

func sevRank(f *Finding) float64 {
	r := map[string]float64{"critical": 2, "warning": 1}[f.Severity]
	return r + f.Confidence/10
}

func (g *groupState) trends(ev *Evaluation, full []bucket, cfg *Config) {
	if len(full) < 6 || full[len(full)-1].start.Sub(full[0].start) < cfg.MinSpan {
		return
	}
	span := full[len(full)-1].start.Sub(full[0].start)
	spanFactor := clamp01(span.Hours() / (3 * cfg.MinSpan.Hours()))

	stable := true
	for _, b := range full {
		if b.minProcs != b.maxProcs || b.minProcs != full[0].minProcs {
			stable = false
			break
		}
	}
	stab := 1.0
	if !stable {
		stab = 0.5
	}

	rss, rssY := trendOf(full, func(b bucket) float64 { return b.minAnon })
	vm, vmY := trendOf(full, func(b bucket) float64 { return b.minVm })
	fds, fdY := trendOf(full, func(b bucket) float64 { return b.minFD })
	thr, thrY := trendOf(full, func(b bucket) float64 { return b.minThr })
	swp, _ := trendOf(full, func(b bucket) float64 { return b.minSwap })
	ev.Trends["rss_anon_floor_bytes"] = Trend{rss.Slope, rss.R2}
	ev.Trends["vm_data_floor_bytes"] = Trend{vm.Slope, vm.R2}
	ev.Trends["open_fds_floor"] = Trend{fds.Slope, fds.R2}
	ev.Trends["threads_floor"] = Trend{thr.Slope, thr.R2}
	ev.Trends["swap_floor_bytes"] = Trend{swp.Slope, swp.R2}

	// Work vs time: correlate bucket increments of the floor with the CPU
	// work done in the same bucket. A leak per processing cycle follows the
	// work; a leak per elapsed time does not.
	driver, bpcs := "unknown", 0.0
	if len(full) >= 9 {
		var dfloor, dcpu []float64
		for i := 1; i < len(full); i++ {
			dfloor = append(dfloor, rssY[i]-rssY[i-1])
			d := full[i].cpuEnd - full[i-1].cpuEnd
			if d < 0 {
				d = 0
			}
			dcpu = append(dcpu, d)
		}
		r := pearson(dfloor, dcpu)
		ev.Corr["rss_floor_increment__cpu_seconds"] = r
		switch {
		case r >= 0.5:
			driver = "work"
		case math.Abs(r) < 0.2:
			driver = "time"
		}
		cpuTotal := full[len(full)-1].cpuEnd - full[0].cpuEnd
		if cpuTotal > 0 {
			bpcs = (rssY[len(rssY)-1] - rssY[0]) / cpuTotal
			ev.BytesPerCPUSecond = bpcs
		}
	}
	ev.Corr["rss_floor__open_fds_floor"] = pearson(rssY, fdY)
	ev.Corr["rss_floor__threads_floor"] = pearson(rssY, thrY)
	ev.Corr["vm_floor__rss_floor"] = pearson(vmY, rssY)

	conf := func(f fit, min, slope float64, mono float64) float64 {
		return clamp01(f.R2*spanFactor*stab*math.Min(1, slope/(2*min))) * math.Min(1, mono/0.7)
	}

	if rss.Slope >= cfg.LeakMinBytesPerHour && rss.R2 >= cfg.R2Min && monotoneShare(rssY) >= 0.7 &&
		sustained(full, func(b bucket) float64 { return b.minAnon }, rss) {
		f := &Finding{Symptom: SymMemoryLeak, Severity: "warning", Driver: driver,
			Confidence: conf(rss, cfg.LeakMinBytesPerHour, rss.Slope, monotoneShare(rssY)),
			Evidence: map[string]float64{"slope_bytes_per_hour": rss.Slope, "r2": rss.R2,
				"span_seconds": span.Seconds(), "bytes_per_cpu_second": bpcs, "procs_stable": b2f(stable)}}
		if cfg.MemAvailable != nil {
			if avail := cfg.MemAvailable(); avail > 0 {
				f.ETA = time.Duration(avail / rss.Slope * float64(time.Hour))
				f.ETAResource = "memory"
				if f.ETA < 24*time.Hour {
					f.Severity = "critical"
				}
			}
		}
		ev.Findings = append(ev.Findings, f)
	}

	rssRef := math.Max(rss.Slope, 1<<20)
	if vm.Slope >= cfg.VMGrowthMinBytesPerHour && vm.R2 >= cfg.R2Min && monotoneShare(vmY) >= 0.7 &&
		vm.Slope/rssRef >= cfg.VMToRSSRatio && sustained(full, func(b bucket) float64 { return b.minVm }, vm) {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymAddressSpaceLeak, Severity: "warning", Driver: driver,
			Confidence: conf(vm, cfg.VMGrowthMinBytesPerHour, vm.Slope, monotoneShare(vmY)),
			Evidence: map[string]float64{"vm_slope_bytes_per_hour": vm.Slope, "rss_slope_bytes_per_hour": rss.Slope,
				"vm_to_rss_ratio": vm.Slope / rssRef, "r2": vm.R2, "span_seconds": span.Seconds()}})
	}

	if fds.Slope >= cfg.FDMinPerHour && fds.R2 >= cfg.R2Min && monotoneShare(fdY) >= 0.7 &&
		sustained(full, func(b bucket) float64 { return b.minFD }, fds) {
		f := &Finding{Symptom: SymFDLeak, Severity: "warning", Driver: driver,
			Confidence: conf(fds, cfg.FDMinPerHour, fds.Slope, monotoneShare(fdY)),
			Evidence:   map[string]float64{"slope_per_hour": fds.Slope, "r2": fds.R2, "open_fds": ev.Latest.FDs}}
		if lim := ev.Latest.FDLimit; lim > 0 && lim < 1e8 && ev.Latest.FDs < lim {
			f.ETA = time.Duration((lim - ev.Latest.FDs) / fds.Slope * float64(time.Hour))
			f.ETAResource = "fd"
			f.Evidence["fd_limit"] = lim
			if f.ETA < 24*time.Hour {
				f.Severity = "critical"
			}
		}
		ev.Findings = append(ev.Findings, f)
	}

	if thr.Slope >= cfg.ThreadMinPerHour && thr.R2 >= cfg.R2Min && monotoneShare(thrY) >= 0.7 &&
		sustained(full, func(b bucket) float64 { return b.minThr }, thr) {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymThreadLeak, Severity: "warning", Driver: driver,
			Confidence: conf(thr, cfg.ThreadMinPerHour, thr.Slope, monotoneShare(thrY)),
			Evidence:   map[string]float64{"slope_per_hour": thr.Slope, "r2": thr.R2, "threads": ev.Latest.Threads}})
	}

	if swp.Slope >= cfg.SwapMinBytesPerHour && swp.R2 >= cfg.R2Min && ev.Latest.Swap > 0 {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymSwapping, Severity: "warning",
			Confidence: clamp01(swp.R2 * spanFactor),
			Evidence:   map[string]float64{"slope_bytes_per_hour": swp.Slope, "swap_bytes": ev.Latest.Swap}})
	}
}

// rates evaluates the fine-window detectors.
func (g *groupState) rates(ev *Evaluation, cfg *Config) {
	n := len(g.fine)
	if n < 2 {
		return
	}
	last := g.fine[n-1]
	var win []Sample
	for _, s := range g.fine {
		if last.T.Sub(s.T) <= cfg.RateWindow {
			win = append(win, s)
		}
	}
	if len(win) < 8 || win[len(win)-1].T.Sub(win[0].T) < cfg.RateWindow*8/10 {
		return
	}
	var cpu, vol, nonvol, minf, majf, io []float64
	for i := 1; i < len(win); i++ {
		dt := win[i].T.Sub(win[i-1].T).Seconds()
		if dt <= 0 {
			continue
		}
		r := func(a, b float64) float64 {
			if b < a {
				return 0
			}
			return (b - a) / dt
		}
		cpu = append(cpu, r(win[i-1].CPU, win[i].CPU))
		vol = append(vol, r(win[i-1].CtxVol, win[i].CtxVol))
		nonvol = append(nonvol, r(win[i-1].CtxNonvol, win[i].CtxNonvol))
		minf = append(minf, r(win[i-1].MinFlt, win[i].MinFlt))
		majf = append(majf, r(win[i-1].MajFlt, win[i].MajFlt))
		io = append(io, r(win[i-1].IOBytes, win[i].IOBytes))
	}
	if len(cpu) == 0 {
		return
	}
	ev.Rates["cpu_cores"] = mean(cpu)
	ev.Rates["voluntary_ctx_per_sec"] = mean(vol)
	ev.Rates["nonvoluntary_ctx_per_sec"] = mean(nonvol)
	ev.Rates["minor_faults_per_sec"] = mean(minf)
	ev.Rates["major_faults_per_sec"] = mean(majf)
	ev.Rates["io_bytes_per_sec"] = mean(io)

	running := 0
	for _, s := range win {
		if s.Running >= 1 {
			running++
		}
	}
	runShare := float64(running) / float64(len(win))
	c := cv(cpu)
	if mean(cpu) >= cfg.BusyLoopCores && c <= cfg.BusyLoopMaxCV && runShare >= 0.8 &&
		mean(vol) < cfg.BusyLoopMaxVolCtx && mean(io) < 1<<20 {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymCPUBusyLoop, Severity: "warning",
			Confidence: clamp01(1 - c/cfg.BusyLoopMaxCV*0.5),
			Evidence: map[string]float64{"cpu_cores": mean(cpu), "cpu_cv": c, "running_share": runShare,
				"voluntary_ctx_per_sec": mean(vol), "io_bytes_per_sec": mean(io)}})
	}
	if mean(nonvol) >= cfg.NonvolCtxPerSec {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymSchedContention, Severity: "warning",
			Confidence: clamp01(mean(nonvol) / (2 * cfg.NonvolCtxPerSec)),
			Evidence:   map[string]float64{"nonvoluntary_ctx_per_sec": mean(nonvol), "cpu_cores": mean(cpu)}})
	}
	if mean(minf) >= cfg.MinorFaultsPerSec {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymMinorFaultStorm, Severity: "warning",
			Confidence: clamp01(mean(minf) / (2 * cfg.MinorFaultsPerSec)),
			Evidence:   map[string]float64{"minor_faults_per_sec": mean(minf)}})
	}
	if mean(majf) >= cfg.MajorFaultsPerSec {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymMajorFaultPress, Severity: "warning",
			Confidence: clamp01(mean(majf) / (2 * cfg.MajorFaultsPerSec)),
			Evidence:   map[string]float64{"major_faults_per_sec": mean(majf)}})
	}

	blocked := 0
	wch := map[string]int{}
	for _, s := range win {
		if s.Blocked >= 1 {
			blocked++
			if s.TopWchan != "" {
				wch[s.TopWchan]++
			}
		}
	}
	if share := float64(blocked) / float64(len(win)); share >= cfg.BlockedShare {
		top, tn := "", 0
		for k, v := range wch {
			if v > tn || (v == tn && k < top) {
				top, tn = k, v
			}
		}
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymBlockedIO, Severity: "warning", Detail: top,
			Confidence: clamp01(share), Evidence: map[string]float64{"blocked_share": share}})
	}

	// Zombies present in every sample of the last ZombieMinAge.
	zn, zt := 0, 0
	for _, s := range g.fine {
		if last.T.Sub(s.T) <= cfg.ZombieMinAge {
			zt++
			if s.Zombie >= 1 {
				zn++
			}
		}
	}
	if zt >= 8 && zn == zt && g.fine[0].T.Before(last.T.Add(-cfg.ZombieMinAge*9/10)) {
		ev.Findings = append(ev.Findings, &Finding{Symptom: SymZombies, Severity: "info", Confidence: 1,
			Evidence: map[string]float64{"zombies": float64(last.Zombie)}})
	}
}

// sawtooth measures the amplitude of the anonymous RSS in the fine window.
func (g *groupState) sawtooth(ev *Evaluation) {
	if len(g.fine) < 8 {
		return
	}
	v := make([]float64, len(g.fine))
	for i, s := range g.fine {
		v[i] = s.anon()
	}
	ev.Sawtooth = percentile(v, 0.95) - percentile(v, 0.05)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Describe renders the evidence of a finding as a short stable string; values
// are rounded to two significant digits so the text changes rarely.
func (f *Finding) Describe() string {
	keys := make([]string, 0, len(f.Evidence))
	for k := range f.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		if s != "" {
			s += " "
		}
		s += fmt.Sprintf("%s=%.2g", k, f.Evidence[k])
	}
	if f.Detail != "" {
		s += " detail=" + f.Detail
	}
	if f.ETA > 0 {
		s += fmt.Sprintf(" eta_%s_h=%.2g", f.ETAResource, f.ETA.Hours())
	}
	return s
}
