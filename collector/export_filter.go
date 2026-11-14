package collector

import "time"

// exportFilter decides which groups are exported. It limits cardinality for
// hosts with many mostly idle processes: a group is exported while its
// resident memory or its CPU usage is above a threshold, and for a hold time
// after it last was, so series do not appear and vanish with every spike.
type exportFilter struct {
	minResident uint64
	minCores    float64
	hold        time.Duration

	qualified map[string]time.Time
	prevCPU   map[string]float64
	prevAt    map[string]time.Time
}

func newExportFilter(minResident uint64, minCores float64, hold time.Duration) *exportFilter {
	if hold == 0 {
		hold = 30 * time.Minute
	}
	return &exportFilter{minResident: minResident, minCores: minCores, hold: hold,
		qualified: map[string]time.Time{}, prevCPU: map[string]float64{}, prevAt: map[string]time.Time{}}
}

func (f *exportFilter) enabled() bool { return f != nil && (f.minResident > 0 || f.minCores > 0) }

// allow records the observation and reports whether the group is exported.
func (f *exportFilter) allow(name string, resident uint64, cpuSeconds float64, now time.Time) bool {
	if !f.enabled() {
		return true
	}
	cores := 0.0
	if at, ok := f.prevAt[name]; ok {
		if dt := now.Sub(at).Seconds(); dt > 0 && cpuSeconds >= f.prevCPU[name] {
			cores = (cpuSeconds - f.prevCPU[name]) / dt
		}
	}
	f.prevCPU[name], f.prevAt[name] = cpuSeconds, now
	if (f.minResident > 0 && resident >= f.minResident) || (f.minCores > 0 && cores >= f.minCores) {
		f.qualified[name] = now
	}
	last, ok := f.qualified[name]
	if !ok {
		return false
	}
	if now.Sub(last) > f.hold {
		delete(f.qualified, name)
		return false
	}
	return true
}

// forget drops state of groups that have not been seen for a day.
func (f *exportFilter) forget(now time.Time) {
	for n, at := range f.prevAt {
		if now.Sub(at) > 24*time.Hour {
			delete(f.prevAt, n)
			delete(f.prevCPU, n)
			delete(f.qualified, n)
		}
	}
}
