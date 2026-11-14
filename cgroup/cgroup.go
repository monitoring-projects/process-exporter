// Package cgroup reads memory, CPU, pids and pressure data of the cgroup a
// process belongs to, for both cgroup v1 (including hybrid hosts) and v2.
//
// Paths come from /proc/<pid>/cgroup, files from a cgroup file system root
// (default /sys/fs/cgroup, in a container the host's mounted read-only).
package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// unlimited is the threshold above which a v1 limit means "no limit".
const unlimited = uint64(1) << 62

// PSI holds pressure stall information of one resource.
type PSI struct {
	Valid                bool
	SomeSec, FullSec     float64 // cumulative stall time
	SomeAvg10, FullAvg10 float64 // percent, last 10 s
}

// Stats is the data of one cgroup. Zero limits mean unlimited.
type Stats struct {
	Path    string
	Version string // v1 or v2

	MemUsage, MemLimit, MemSwap                        uint64
	MemAnon, MemFile, MemShmem, MemKernel, MemSlab     uint64
	MemSock, MemMapped, MemInactiveFile, MemActiveFile uint64
	EventMax, EventHigh, EventOOM, EventOOMKill        uint64

	CPUUsageSec               float64
	Periods, ThrottledPeriods uint64
	ThrottledSec              float64
	CPULimitCores             float64

	CPU, Memory, IO PSI

	PidsCur, PidsMax uint64
	Procs            int // processes of the group in this cgroup
}

// NonReclaimable approximates the memory the kernel cannot drop under
// pressure: anonymous and shared memory plus unreclaimable kernel memory
// (kernel stacks, page tables, unreclaimable slab; v2 only, v1 does not split
// kernel memory into reclaimable and not).
func (s Stats) NonReclaimable() uint64 { return s.MemAnon + s.MemShmem + s.MemKernel }

// Reader reads cgroup files. It caches results per Refresh cycle.
type Reader struct {
	Root, Procfs string
	version      string
	cache        map[string]Stats
}

// NewReader detects the cgroup layout below root: v2 when root has
// cgroup.controllers, v1 when it has a memory controller (hybrid hosts too),
// "" when neither is readable.
func NewReader(root, procfs string) *Reader {
	r := &Reader{Root: root, Procfs: procfs, cache: map[string]Stats{}}
	switch {
	case exists(filepath.Join(root, "cgroup.controllers")):
		r.version = "v2"
	case exists(filepath.Join(root, "memory")):
		r.version = "v1"
	}
	return r
}

// Version returns v1, v2 or "".
func (r *Reader) Version() string { return r.version }

// Refresh drops the cache; call once per sampling cycle.
func (r *Reader) Refresh() { r.cache = map[string]Stats{} }

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// pidPaths returns the memory/unified path and the cpu path of a process.
func (r *Reader) pidPaths(pid int) (mem, cpu, pids string, ok bool) {
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", r.Procfs, pid))
	if err != nil {
		return "", "", "", false
	}
	return parseProcCgroup(string(b), r.version)
}

// parseProcCgroup parses /proc/pid/cgroup ("id:controllers:path" lines).
func parseProcCgroup(content, version string) (mem, cpu, pids string, ok bool) {
	for _, l := range strings.Split(content, "\n") {
		f := strings.SplitN(l, ":", 3)
		if len(f) != 3 {
			continue
		}
		if version == "v2" {
			if f[0] == "0" && f[1] == "" {
				return f[2], f[2], f[2], true
			}
			continue
		}
		for _, c := range strings.Split(f[1], ",") {
			switch c {
			case "memory":
				mem = f[2]
			case "cpu":
				cpu = f[2]
			case "pids":
				pids = f[2]
			}
		}
	}
	return mem, cpu, pids, mem != ""
}

// ForPids returns the Stats of every distinct cgroup of the given processes,
// with Procs set to how many of the pids are in it (at most maxPids are read).
func (r *Reader) ForPids(pids []int, maxPids int) []Stats {
	if r.version == "" {
		return nil
	}
	if maxPids > 0 && len(pids) > maxPids {
		pids = pids[:maxPids]
	}
	count := map[string]int{}
	var order []string
	for _, pid := range pids {
		mem, cpu, pp, ok := r.pidPaths(pid)
		if !ok {
			continue
		}
		key := mem + "|" + cpu + "|" + pp
		if count[key] == 0 {
			order = append(order, key)
			if _, hit := r.cache[key]; !hit {
				r.cache[key] = r.read(mem, cpu, pp)
			}
		}
		count[key]++
	}
	var out []Stats
	for _, k := range order {
		s := r.cache[k]
		s.Procs = count[k]
		out = append(out, s)
	}
	return out
}

func (r *Reader) read(mem, cpu, pids string) Stats {
	if r.version == "v2" {
		return r.readV2(mem)
	}
	return r.readV1(mem, cpu, pids)
}

func (r *Reader) readV2(path string) Stats {
	d := filepath.Join(r.Root, path)
	s := Stats{Path: path, Version: "v2"}
	s.MemUsage = readUint(filepath.Join(d, "memory.current"))
	s.MemLimit = readUint(filepath.Join(d, "memory.max"))
	s.MemSwap = readUint(filepath.Join(d, "memory.swap.current"))
	st := readKV(filepath.Join(d, "memory.stat"))
	s.MemAnon, s.MemFile, s.MemShmem = st["anon"], st["file"], st["shmem"]
	s.MemKernel, s.MemSlab, s.MemSock = st["kernel"], st["slab"], st["sock"]
	// Unreclaimable kernel memory only: the "kernel" total includes
	// reclaimable slab, which would overstate what pressure cannot free.
	s.MemKernel = st["kernel_stack"] + st["pagetables"] + st["slab_unreclaimable"] + st["percpu"]
	s.MemMapped, s.MemInactiveFile, s.MemActiveFile = st["file_mapped"], st["inactive_file"], st["active_file"]
	ev := readKV(filepath.Join(d, "memory.events"))
	s.EventMax, s.EventHigh, s.EventOOM, s.EventOOMKill = ev["max"], ev["high"], ev["oom"], ev["oom_kill"]
	cs := readKV(filepath.Join(d, "cpu.stat"))
	s.CPUUsageSec = float64(cs["usage_usec"]) / 1e6
	s.Periods, s.ThrottledPeriods = cs["nr_periods"], cs["nr_throttled"]
	s.ThrottledSec = float64(cs["throttled_usec"]) / 1e6
	s.CPULimitCores = parseCPUMax(readString(filepath.Join(d, "cpu.max")))
	s.CPU = readPSI(filepath.Join(d, "cpu.pressure"))
	s.Memory = readPSI(filepath.Join(d, "memory.pressure"))
	s.IO = readPSI(filepath.Join(d, "io.pressure"))
	s.PidsCur = readUint(filepath.Join(d, "pids.current"))
	s.PidsMax = readUint(filepath.Join(d, "pids.max"))
	return s
}

func (r *Reader) readV1(mem, cpu, pids string) Stats {
	m := filepath.Join(r.Root, "memory", mem)
	s := Stats{Path: mem, Version: "v1"}
	s.MemUsage = readUint(filepath.Join(m, "memory.usage_in_bytes"))
	if l := readUint(filepath.Join(m, "memory.limit_in_bytes")); l < unlimited {
		s.MemLimit = l
	}
	st := readKV(filepath.Join(m, "memory.stat"))
	s.MemAnon = st["rss"]
	s.MemFile, s.MemShmem, s.MemMapped = st["cache"], st["shmem"], st["mapped_file"]
	s.MemInactiveFile, s.MemActiveFile = st["inactive_file"], st["active_file"]
	s.MemSwap = st["swap"]
	s.EventMax = readUint(filepath.Join(m, "memory.failcnt"))
	oc := readKV(filepath.Join(m, "memory.oom_control"))
	s.EventOOM, s.EventOOMKill = oc["under_oom"], oc["oom_kill"]
	if cpu != "" {
		c := filepath.Join(r.Root, "cpu", cpu)
		cs := readKV(filepath.Join(c, "cpu.stat"))
		s.Periods, s.ThrottledPeriods = cs["nr_periods"], cs["nr_throttled"]
		s.ThrottledSec = float64(cs["throttled_time"]) / 1e9
		quota := readInt(filepath.Join(c, "cpu.cfs_quota_us"))
		period := readInt(filepath.Join(c, "cpu.cfs_period_us"))
		if quota > 0 && period > 0 {
			s.CPULimitCores = float64(quota) / float64(period)
		}
		s.CPUUsageSec = float64(readUint(filepath.Join(r.Root, "cpuacct", cpu, "cpuacct.usage"))) / 1e9
	}
	if pids != "" {
		p := filepath.Join(r.Root, "pids", pids)
		s.PidsCur = readUint(filepath.Join(p, "pids.current"))
		s.PidsMax = readUint(filepath.Join(p, "pids.max"))
	}
	return s
}

// ReadHostPSI reads /proc/pressure/{cpu,memory,io}; resources the kernel does
// not provide are not Valid.
func ReadHostPSI(procfs string) (cpu, memory, io PSI) {
	return readPSI(procfs + "/pressure/cpu"), readPSI(procfs + "/pressure/memory"), readPSI(procfs + "/pressure/io")
}

// Rollup combines the cgroups of one process group. Counters are summed; the
// limit related fields describe the cgroup closest to its memory limit.
type Rollup struct {
	Version string
	Cgroups int
	// Primary is the path of the cgroup with most processes of the group.
	Primary string

	MemUsage, MemNonReclaim, MemFile, MemAnon, MemShmem, MemKernel uint64
	// LimitBytes and LimitNonReclaim belong to the cgroup with the highest
	// non-reclaimable/limit ratio; zero when no cgroup has a memory limit.
	LimitBytes, LimitNonReclaim uint64

	EventMax, EventOOMKill uint64

	CPUUsageSec, ThrottledSec float64
	Periods, ThrottledPeriods uint64
	CPULimitCores             float64
	CPU, Memory, IO           PSI
	PidsCur                   uint64
	PidsLimit, PidsLimitCur   uint64
}

// Combine builds the rollup of a group.
func Combine(all []Stats) Rollup {
	var r Rollup
	best, bestProcs := -1.0, 0
	pbest := -1.0
	for _, s := range all {
		if r.Version == "" {
			r.Version = s.Version
		}
		r.Cgroups++
		if s.Procs > bestProcs {
			bestProcs, r.Primary = s.Procs, s.Path
		}
		r.MemUsage += s.MemUsage
		r.MemNonReclaim += s.NonReclaimable()
		r.MemFile += s.MemFile
		r.MemAnon += s.MemAnon
		r.MemShmem += s.MemShmem
		r.MemKernel += s.MemKernel
		r.EventMax += s.EventMax
		r.EventOOMKill += s.EventOOMKill
		r.CPUUsageSec += s.CPUUsageSec
		r.ThrottledSec += s.ThrottledSec
		r.Periods += s.Periods
		r.ThrottledPeriods += s.ThrottledPeriods
		if s.CPULimitCores > 0 && (r.CPULimitCores == 0 || s.CPULimitCores < r.CPULimitCores) {
			r.CPULimitCores = s.CPULimitCores
		}
		r.CPU.add(s.CPU)
		r.Memory.add(s.Memory)
		r.IO.add(s.IO)
		r.PidsCur += s.PidsCur
		if s.MemLimit > 0 {
			if ratio := float64(s.NonReclaimable()) / float64(s.MemLimit); ratio > best {
				best, r.LimitBytes, r.LimitNonReclaim = ratio, s.MemLimit, s.NonReclaimable()
			}
		}
		if s.PidsMax > 0 {
			if ratio := float64(s.PidsCur) / float64(s.PidsMax); ratio > pbest {
				pbest, r.PidsLimit, r.PidsLimitCur = ratio, s.PidsMax, s.PidsCur
			}
		}
	}
	return r
}

func (p *PSI) add(o PSI) {
	if !o.Valid {
		return
	}
	p.Valid = true
	p.SomeSec += o.SomeSec
	p.FullSec += o.FullSec
	if o.SomeAvg10 > p.SomeAvg10 {
		p.SomeAvg10 = o.SomeAvg10
	}
	if o.FullAvg10 > p.FullAvg10 {
		p.FullAvg10 = o.FullAvg10
	}
}

// ---- parsing helpers -------------------------------------------------------

func readString(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readUint parses an unsigned value; "max" and unreadable files give 0.
func readUint(p string) uint64 {
	v, err := strconv.ParseUint(readString(p), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readInt(p string) int64 {
	v, err := strconv.ParseInt(readString(p), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// readKV parses flat "key value" files; keys that are not numbers are skipped.
func readKV(p string) map[string]uint64 {
	res := map[string]uint64{}
	b, err := os.ReadFile(p)
	if err != nil {
		return res
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			res[f[0]] = v
		}
	}
	return res
}

// parseCPUMax parses v2 cpu.max ("max 100000" or "200000 100000") to cores.
func parseCPUMax(s string) float64 {
	f := strings.Fields(s)
	if len(f) != 2 || f[0] == "max" {
		return 0
	}
	q, e1 := strconv.ParseFloat(f[0], 64)
	p, e2 := strconv.ParseFloat(f[1], 64)
	if e1 != nil || e2 != nil || p == 0 {
		return 0
	}
	return q / p
}

// readPSI parses "some avg10=0.00 avg60=0.00 avg300=0.00 total=123" lines.
func readPSI(p string) PSI {
	b, err := os.ReadFile(p)
	if err != nil {
		return PSI{}
	}
	return parsePSI(string(b))
}

func parsePSI(content string) PSI {
	var psi PSI
	for _, l := range strings.Split(content, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || (f[0] != "some" && f[0] != "full") {
			continue
		}
		var avg10, total float64
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "avg10":
				avg10 = x
			case "total":
				total = x / 1e6
			}
		}
		psi.Valid = true
		if f[0] == "some" {
			psi.SomeAvg10, psi.SomeSec = avg10, total
		} else {
			psi.FullAvg10, psi.FullSec = avg10, total
		}
	}
	return psi
}
