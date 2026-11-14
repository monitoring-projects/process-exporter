package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseProcCgroup(t *testing.T) {
	v1 := "12:pids:/kubepods/burstable/pod1/c1\n11:memory:/kubepods/burstable/pod1/c1\n4:cpu,cpuacct:/kubepods/burstable/pod1/c1\n1:name=systemd:/x\n0::/unified/x\n"
	m, c, p, ok := parseProcCgroup(v1, "v1")
	if !ok || m != "/kubepods/burstable/pod1/c1" || c != m || p != m {
		t.Fatalf("v1: %q %q %q %v", m, c, p, ok)
	}
	m, _, _, ok = parseProcCgroup("0::/kubepods.slice/pod.slice/cri-x.scope\n", "v2")
	if !ok || m != "/kubepods.slice/pod.slice/cri-x.scope" {
		t.Fatalf("v2: %q %v", m, ok)
	}
	if _, _, _, ok = parseProcCgroup("garbage", "v1"); ok {
		t.Fatal("garbage parsed")
	}
}

func TestParsePSIAndCPUMax(t *testing.T) {
	psi := parsePSI("some avg10=1.50 avg60=0.50 avg300=0.10 total=2500000\nfull avg10=0.25 avg60=0.00 avg300=0.00 total=500000\n")
	if !psi.Valid || psi.SomeAvg10 != 1.5 || psi.SomeSec != 2.5 || psi.FullAvg10 != 0.25 || psi.FullSec != 0.5 {
		t.Fatalf("psi %+v", psi)
	}
	if parsePSI("").Valid {
		t.Fatal("empty psi valid")
	}
	if got := parseCPUMax("200000 100000"); got != 2 {
		t.Fatalf("cpu.max = %v", got)
	}
	if parseCPUMax("max 100000") != 0 || parseCPUMax("") != 0 {
		t.Fatal("unlimited cpu.max must be 0")
	}
}

func TestReaderV2(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	put(t, root, "cgroup.controllers", "cpu memory io pids")
	cg := "kubepods.slice/pod.slice/cri-abc.scope"
	put(t, proc, "42/cgroup", "0::/"+cg+"\n")
	put(t, root, cg+"/memory.current", "1000000000\n")
	put(t, root, cg+"/memory.max", "2000000000\n")
	put(t, root, cg+"/memory.swap.current", "5\n")
	put(t, root, cg+"/memory.stat", "anon 600000000\nfile 300000000\nshmem 50000000\nkernel 99999999\nkernel_stack 10000000\npagetables 10000000\nslab 10\nsock 1\nfile_mapped 7\ninactive_file 100\nactive_file 200\n")
	put(t, root, cg+"/memory.events", "low 0\nhigh 2\nmax 9\noom 1\noom_kill 1\n")
	put(t, root, cg+"/cpu.stat", "usage_usec 3000000\nnr_periods 100\nnr_throttled 30\nthrottled_usec 1500000\n")
	put(t, root, cg+"/cpu.max", "150000 100000\n")
	put(t, root, cg+"/memory.pressure", "some avg10=12.00 avg60=1.00 avg300=0.10 total=4000000\nfull avg10=3.00 avg60=0.00 avg300=0.00 total=1000000\n")
	put(t, root, cg+"/pids.current", "12\n")
	put(t, root, cg+"/pids.max", "max\n")

	r := NewReader(root, proc)
	if r.Version() != "v2" {
		t.Fatalf("version %q", r.Version())
	}
	all := r.ForPids([]int{42, 43}, 0) // 43 does not exist
	if len(all) != 1 || all[0].Procs != 1 {
		t.Fatalf("stats %+v", all)
	}
	s := all[0]
	if s.MemUsage != 1e9 || s.MemLimit != 2e9 || s.MemAnon != 6e8 || s.EventOOMKill != 1 || s.EventMax != 9 ||
		s.CPUUsageSec != 3 || s.ThrottledPeriods != 30 || s.ThrottledSec != 1.5 || s.CPULimitCores != 1.5 ||
		s.PidsCur != 12 || s.PidsMax != 0 || !s.Memory.Valid || s.Memory.SomeAvg10 != 12 || s.Memory.FullSec != 1 {
		t.Fatalf("unexpected stats %+v", s)
	}
	if got := s.NonReclaimable(); got != 6e8+5e7+2e7 {
		t.Fatalf("non reclaimable %d", got)
	}
	ru := Combine(all)
	if ru.LimitBytes != 2e9 || ru.LimitNonReclaim != 6.7e8 || ru.Primary != "/"+cg || ru.ThrottledPeriods != 30 {
		t.Fatalf("rollup %+v", ru)
	}
}

func TestReaderV1Hybrid(t *testing.T) {
	root, proc := t.TempDir(), t.TempDir()
	put(t, root, "memory/memory.limit_in_bytes", "9223372036854771712\n") // marks a v1 root
	cg := "/kubepods/burstable/podx/ctr"
	put(t, proc, "7/cgroup", "11:memory:"+cg+"\n4:cpu,cpuacct:"+cg+"\n12:pids:"+cg+"\n0::/ignored\n")
	put(t, root, "memory"+cg+"/memory.usage_in_bytes", "900\n")
	put(t, root, "memory"+cg+"/memory.limit_in_bytes", "1000\n")
	put(t, root, "memory"+cg+"/memory.stat", "cache 400\nrss 300\nshmem 20\nmapped_file 5\ninactive_file 3\nactive_file 4\nswap 0\n")
	put(t, root, "memory"+cg+"/memory.failcnt", "11\n")
	put(t, root, "memory"+cg+"/memory.oom_control", "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n")
	put(t, root, "cpu"+cg+"/cpu.stat", "nr_periods 10\nnr_throttled 4\nthrottled_time 2000000000\n")
	put(t, root, "cpu"+cg+"/cpu.cfs_quota_us", "200000\n")
	put(t, root, "cpu"+cg+"/cpu.cfs_period_us", "100000\n")
	put(t, root, "cpuacct"+cg+"/cpuacct.usage", "5000000000\n")
	put(t, root, "pids"+cg+"/pids.current", "30\n")
	put(t, root, "pids"+cg+"/pids.max", "100\n")

	r := NewReader(root, proc)
	if r.Version() != "v1" {
		t.Fatalf("version %q", r.Version())
	}
	all := r.ForPids([]int{7}, 0)
	if len(all) != 1 {
		t.Fatalf("stats %+v", all)
	}
	s := all[0]
	if s.MemLimit != 1000 || s.MemAnon != 300 || s.MemFile != 400 || s.EventMax != 11 || s.EventOOMKill != 2 ||
		s.CPULimitCores != 2 || s.CPUUsageSec != 5 || s.ThrottledSec != 2 || s.PidsMax != 100 || s.Memory.Valid {
		t.Fatalf("unexpected stats %+v", s)
	}
	// unlimited limits are reported as 0
	put(t, root, "memory"+cg+"/memory.limit_in_bytes", "9223372036854771712\n")
	r.Refresh()
	if got := r.ForPids([]int{7}, 0)[0].MemLimit; got != 0 {
		t.Fatalf("unlimited limit reported as %d", got)
	}
}

func TestCombineWorstLimitAndCounters(t *testing.T) {
	a := Stats{Path: "/a", Version: "v1", MemAnon: 100, MemLimit: 1000, ThrottledPeriods: 1, Periods: 10, Procs: 1}
	b := Stats{Path: "/b", Version: "v1", MemAnon: 900, MemLimit: 1000, ThrottledPeriods: 2, Periods: 10, Procs: 3, PidsCur: 5, PidsMax: 10}
	c := Stats{Path: "/c", Version: "v1", MemAnon: 5000, Procs: 1} // unlimited
	ru := Combine([]Stats{a, b, c})
	if ru.Cgroups != 3 || ru.Primary != "/b" || ru.LimitNonReclaim != 900 || ru.ThrottledPeriods != 3 || ru.Periods != 20 ||
		ru.PidsLimit != 10 || ru.PidsLimitCur != 5 {
		t.Fatalf("rollup %+v", ru)
	}
	if NewReader(t.TempDir(), t.TempDir()).Version() != "" {
		t.Fatal("empty root must not detect a version")
	}
}
