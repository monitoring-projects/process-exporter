package diagnose

import (
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/Monitoring-Projects/process-exporter/proc"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	symptomDesc = prometheus.NewDesc("namedprocess_diag_symptom",
		"1 while a symptom is active for the group (series exists only while active)",
		[]string{"groupname", "symptom", "severity"}, nil)
	confidenceDesc = prometheus.NewDesc("namedprocess_diag_confidence",
		"confidence 0..1 of an active symptom",
		[]string{"groupname", "symptom"}, nil)
	verdictDesc = prometheus.NewDesc("namedprocess_diag_verdict_info",
		"top symptom of the group with its driver and rounded evidence as labels (1 while active)",
		[]string{"groupname", "verdict", "driver", "severity", "evidence"}, nil)
	etaDesc = prometheus.NewDesc("namedprocess_diag_predicted_exhaustion_seconds",
		"predicted seconds until the resource is exhausted at the current trend (memory: host MemAvailable)",
		[]string{"groupname", "resource"}, nil)
	trendDesc = prometheus.NewDesc("namedprocess_diag_trend_per_hour",
		"fitted growth per hour of the per-bucket floor of a signal (bytes or count)",
		[]string{"groupname", "resource"}, nil)
	trendR2Desc = prometheus.NewDesc("namedprocess_diag_trend_r2",
		"R2 of the fitted trend", []string{"groupname", "resource"}, nil)
	rateDesc = prometheus.NewDesc("namedprocess_diag_rate",
		"mean rate over the rate window (cpu_cores, *_ctx_per_sec, *_faults_per_sec, io_bytes_per_sec)",
		[]string{"groupname", "signal"}, nil)
	corrDesc = prometheus.NewDesc("namedprocess_diag_correlation",
		"Pearson correlation between two sampled signals of the group",
		[]string{"groupname", "pair"}, nil)
	memDesc = prometheus.NewDesc("namedprocess_diag_memory_bytes",
		"memory breakdown from /proc/pid/status summed over the group (only for flagged or detail groups)",
		[]string{"groupname", "memtype"}, nil)
	sawDesc = prometheus.NewDesc("namedprocess_diag_sawtooth_amplitude_bytes",
		"p95-p5 of the anonymous RSS in the sample window (cyclic workloads)",
		[]string{"groupname"}, nil)
	bpcsDesc = prometheus.NewDesc("namedprocess_diag_leak_bytes_per_cpu_second",
		"floor growth in bytes per CPU second of work over the observed span",
		[]string{"groupname"}, nil)
	observedDesc = prometheus.NewDesc("namedprocess_diag_observed_seconds",
		"span covered by the complete floor buckets", []string{"groupname"}, nil)
	restartsDesc = prometheus.NewDesc("namedprocess_diag_restarts",
		"process-group restarts seen in the floor span", []string{"groupname"}, nil)
	mapsDesc = prometheus.NewDesc("namedprocess_diag_map_count",
		"number of memory mappings (lines of /proc/pid/maps), max over the group's processes",
		[]string{"groupname"}, nil)
	analyzedDesc = prometheus.NewDesc("namedprocess_diag_groups_analyzed",
		"groups currently analysed", nil, nil)
	flaggedDesc = prometheus.NewDesc("namedprocess_diag_groups_flagged",
		"groups with at least one active symptom", nil, nil)
	evalDesc = prometheus.NewDesc("namedprocess_diag_eval_seconds",
		"duration of the last analysis pass", nil, nil)
)

// Engine keeps the history of every analysed group.
type Engine struct {
	cfg    Config
	groups *regexp.Regexp

	mu       sync.Mutex
	state    map[string]*groupState
	evalTime time.Duration
	lastNow  time.Time
}

// New creates an engine analysing the groups matching groups (nil: all).
func New(cfg Config, groups *regexp.Regexp) *Engine {
	cfg.defaults()
	return &Engine{cfg: cfg, groups: groups, state: map[string]*groupState{}}
}

// Observe records one sample per analysed group and re-evaluates it.
func (e *Engine) Observe(now time.Time, groups proc.GroupByName, extras map[string]proc.GroupExtra, maps map[string]int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t0 := time.Now()
	e.lastNow = now

	for name, g := range groups {
		if e.groups != nil && !e.groups.MatchString(name) {
			continue
		}
		st := e.state[name]
		if st == nil {
			if len(e.state) >= e.cfg.MaxGroups {
				continue
			}
			st = &groupState{active: map[string]*Finding{}, evidence: map[string]evidenceText{}, lastWarn: map[string]time.Time{}}
			e.state[name] = st
		}
		if n := len(st.fine); n > 0 && now.Sub(st.fine[n-1].T) < 2*time.Second {
			continue
		}
		x := extras[name]
		s := Sample{
			T: now, Procs: g.Procs,
			RssAnon: float64(x.Ext.RssAnonBytes), Rss: float64(g.Memory.ResidentBytes),
			RssFile: float64(x.Ext.RssFileBytes), RssShmem: float64(x.Ext.RssShmemBytes),
			VmData: float64(x.Ext.VmDataBytes), Virtual: float64(g.Memory.VirtualBytes),
			VmHWM: float64(x.Ext.VmHWMBytes), VmPTE: float64(x.Ext.VmPTEBytes), VmLck: float64(x.Ext.VmLckBytes),
			Swap: float64(g.Memory.VmSwapBytes),
			FDs:  float64(g.OpenFDs), FDLimit: float64(x.FDLimitMin), Threads: float64(g.NumThreads),
			CPU:    g.CPUUserTime + g.CPUSystemTime,
			CtxVol: float64(g.CtxSwitchVoluntary), CtxNonvol: float64(g.CtxSwitchNonvoluntary),
			MinFlt: float64(g.MinorPageFaults), MajFlt: float64(g.MajorPageFaults),
			IOBytes: float64(g.ReadBytes + g.WriteBytes),
			Running: g.States.Running, Sleeping: g.States.Sleeping, Blocked: g.States.Waiting, Zombie: g.States.Zombie,
		}
		if !g.OldestStartTime.IsZero() && g.Procs > 0 {
			s.Start = g.OldestStartTime.Unix()
		}
		s.TopWchan = topWchan(g.Wchans)
		if m, ok := maps[name]; ok {
			s.MapCount = float64(m)
		}
		st.add(s, &e.cfg)
		st.lastEval = evaluate(st, &e.cfg, now)
		for _, f := range st.lastEval.Findings {
			cp := *f
			st.active[f.Symptom] = &cp
			st.lastWarn[f.Symptom] = now
		}
	}

	// Forget groups that have been gone for longer than the window.
	for name, st := range e.state {
		if now.Sub(st.lastSeen) > e.cfg.FloorSpan {
			delete(e.state, name)
		}
	}
	e.evalTime = time.Since(t0)
}

func topWchan(w map[string]int) string {
	best, n := "", 0
	for k, v := range w {
		if k == "" || k == "0" {
			continue
		}
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

// activeFindings returns the findings still within the hold time, worst first.
func (e *Engine) activeFindings(st *groupState, now time.Time) []*Finding {
	var out []*Finding
	for sym, f := range st.active {
		if now.Sub(st.lastWarn[sym]) <= e.cfg.Hold {
			out = append(out, f)
		} else {
			delete(st.active, sym)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if sevRank(out[i]) != sevRank(out[j]) {
			return sevRank(out[i]) > sevRank(out[j])
		}
		return out[i].Symptom < out[j].Symptom
	})
	return out
}

// Flagged returns the group names that currently have an active symptom.
func (e *Engine) Flagged(now time.Time) map[string][]*Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := map[string][]*Finding{}
	for name, st := range e.state {
		if fs := e.activeFindings(st, now); len(fs) > 0 {
			res[name] = fs
		}
	}
	return res
}

// Describe implements prometheus.Collector.
func (e *Engine) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{symptomDesc, confidenceDesc, verdictDesc, etaDesc, trendDesc, trendR2Desc,
		rateDesc, corrDesc, memDesc, sawDesc, bpcsDesc, observedDesc, restartsDesc, mapsDesc, analyzedDesc, flaggedDesc, evalDesc} {
		ch <- d
	}
}

// Collect emits the derived series. Healthy groups emit nothing.
func (e *Engine) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.lastNow
	if now.IsZero() {
		now = time.Now()
	}
	g := func(d *prometheus.Desc, v float64, l ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, l...)
	}
	flagged := 0
	for name, st := range e.state {
		fs := e.activeFindings(st, now)
		detail := e.cfg.DetailAlways != nil && e.cfg.DetailAlways(name)
		if len(fs) > 0 {
			flagged++
		}
		if len(fs) == 0 && !detail {
			continue
		}
		ev := st.lastEval
		for _, f := range fs {
			g(symptomDesc, 1, name, f.Symptom, f.Severity)
			g(confidenceDesc, f.Confidence, name, f.Symptom)
			if f.ETA > 0 {
				g(etaDesc, f.ETA.Seconds(), name, f.ETAResource)
			}
		}
		if len(fs) > 0 {
			top := fs[0]
			driver := top.Driver
			if driver == "" {
				driver = "none"
			}
			g(verdictDesc, 1, name, top.Symptom, driver, top.Severity, e.evidence(st, top, now))
		}
		if len(ev.Trends) > 0 {
			for k, t := range ev.Trends {
				g(trendDesc, t.PerHour, name, k)
				g(trendR2Desc, t.R2, name, k)
			}
		}
		for k, v := range ev.Rates {
			g(rateDesc, v, name, k)
		}
		for k, v := range ev.Corr {
			g(corrDesc, v, name, k)
		}
		l := ev.Latest
		for k, v := range map[string]float64{"anon": l.RssAnon, "file": l.RssFile, "shmem": l.RssShmem, "data": l.VmData,
			"peak": l.VmHWM, "pagetables": l.VmPTE, "locked": l.VmLck} {
			g(memDesc, v, name, k)
		}
		g(sawDesc, ev.Sawtooth, name)
		if ev.BytesPerCPUSecond != 0 {
			g(bpcsDesc, ev.BytesPerCPUSecond, name)
		}
		g(observedDesc, ev.Observed.Seconds(), name)
		g(restartsDesc, float64(ev.Restarts), name)
		if l.MapCount > 0 {
			g(mapsDesc, l.MapCount, name)
		}
	}
	g(analyzedDesc, float64(len(e.state)))
	g(flaggedDesc, float64(flagged))
	g(evalDesc, e.evalTime.Seconds())
}

// evidence returns the evidence label text, refreshed at most once per hold
// time so the label does not churn series.
func (e *Engine) evidence(st *groupState, f *Finding, now time.Time) string {
	if c, ok := st.evidence[f.Symptom]; ok && now.Sub(c.at) < e.cfg.Hold {
		return c.text
	}
	t := f.Describe()
	st.evidence[f.Symptom] = evidenceText{t, now}
	return t
}
