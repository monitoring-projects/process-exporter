package diagnose

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Monitoring-Projects/process-exporter/proc"
)

// Replays 30 days of hourly RSS of two anonymised real workloads: a leaky
// worker that grows about 12-18 MB/h under a per-cycle sawtooth and a steady
// worker that stays at about 1.4-1.7 GB (+0.6 MB/h). Replacements of the
// process (RSS drops by more than half) are replayed as restarts.
func TestReplayRealLeakAndFlatWorkload(t *testing.T) {
	f, err := os.Open("testdata/leaky_vs_steady_rss_30d_1h.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type row struct {
		t             time.Time
		leaky, steady float64
	}
	var rows []row
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		c := strings.Split(sc.Text(), "\t")
		ep, _ := strconv.ParseInt(c[0], 10, 64)
		leaky, _ := strconv.ParseFloat(c[1], 64)
		steady, _ := strconv.ParseFloat(c[2], 64)
		rows = append(rows, row{time.Unix(ep, 0).UTC(), leaky, steady})
	}
	if len(rows) < 700 {
		t.Fatalf("only %d rows", len(rows))
	}
	cfg := Config{Bucket: time.Hour, FloorSpan: 24 * time.Hour, MinSpan: 8 * time.Hour, Window: 3 * time.Hour,
		RateWindow: 3 * time.Hour, MinLife: time.Hour, Hold: 6 * time.Hour,
		MemAvailable: func() float64 { return 60 << 30 }}
	e := New(cfg, regexp.MustCompile(".+"))
	startLeaky, startSteady := rows[0].t, rows[0].t
	prevLeaky, prevSteady := rows[0].leaky, rows[0].steady
	flaggedLeaky, flaggedSteady := 0, 0
	var leakyAtPeak *Finding
	for i, r := range rows {
		if r.leaky < prevLeaky/2 {
			startLeaky = r.t
		}
		if r.steady < prevSteady/2 {
			startSteady = r.t
		}
		prevLeaky, prevSteady = r.leaky, r.steady
		g := func(mib float64, start time.Time) proc.Group {
			return proc.Group{Procs: 1, OldestStartTime: start, Memory: proc.Memory{ResidentBytes: uint64(mib * mib_)}}
		}
		x := func(mib float64) proc.GroupExtra {
			return proc.GroupExtra{Ext: proc.MemoryExt{RssAnonBytes: uint64(mib * mib_)}}
		}
		e.Observe(r.t, proc.GroupByName{"leaky": g(r.leaky, startLeaky), "steady": g(r.steady, startSteady)},
			map[string]proc.GroupExtra{"leaky": x(r.leaky), "steady": x(r.steady)}, nil)
		fl := e.Flagged(r.t)
		for _, ff := range fl["leaky"] {
			if ff.Symptom == SymMemoryLeak {
				flaggedLeaky++
				// the end of the first long growth period: end of the long growth period before the 10-27 redeploy
				if r.t.Format("01-02T15") == "10-25T05" {
					leakyAtPeak = ff
				}
			}
		}
		for _, ff := range fl["steady"] {
			if ff.Symptom == SymMemoryLeak {
				flaggedSteady++
				t.Logf("steady flagged %s slope=%.1f MiB/h r2=%.2f span=%.0fh rss=%.0f", r.t.Format("01-02T15"), ff.Evidence["slope_bytes_per_hour"]/mib_, ff.Evidence["r2"], ff.Evidence["span_seconds"]/3600, r.steady)
			}
		}
		_ = i
	}
	if flaggedLeaky < 200 {
		t.Errorf("leaky worker flagged in only %d of %d hours", flaggedLeaky, len(rows))
	}
	if flaggedSteady != 0 {
		t.Errorf("steady worker flagged %d times (it is steady)", flaggedSteady)
	}
	if leakyAtPeak == nil {
		t.Fatalf("not flagged at the end of the 10-08..10-26 growth period")
	}
	if got := leakyAtPeak.Evidence["slope_bytes_per_hour"] / mib_; got < 10 || got > 25 {
		t.Errorf("slope %.1f MiB/h, want 10-25 (measured 12-18)", got)
	}
}

const mib_ = 1 << 20
