package collector

import (
	"testing"
	"time"
)

func TestClassifyFD(t *testing.T) {
	for in, want := range map[string]string{
		"socket:[123]":               "socket",
		"pipe:[9]":                   "pipe",
		"anon_inode:[eventpoll]":     "anon_inode",
		"/dev/infiniband/rdma_cm":    "infiniband",
		"/dev/shm/segment (deleted)": "shm",
		"/SYSV011baf7b (deleted)":    "shm",
		"/memfd:x (deleted)":         "memfd",
		"/dev/null":                  "device",
		"/proc/1/status":             "procfs",
		"/var/log/app.log":           "file",
		"weird":                      "other",
	} {
		if got := classifyFD(in); got != want {
			t.Errorf("classifyFD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportFilterHysteresis(t *testing.T) {
	f := newExportFilter(100, 0.5, 10*time.Minute)
	t0 := time.Unix(1000, 0)
	// idle group: never exported
	if f.allow("idle", 10, 1, t0) {
		t.Fatal("idle group exported")
	}
	// big group exported, then stays during the hold time, then dropped
	if !f.allow("big", 500, 1, t0) {
		t.Fatal("big group not exported")
	}
	if !f.allow("big", 10, 1, t0.Add(5*time.Minute)) {
		t.Fatal("group dropped inside hold time")
	}
	if f.allow("big", 10, 1, t0.Add(20*time.Minute)) {
		t.Fatal("group still exported after hold time")
	}
	// CPU qualifies after the second observation
	f.allow("busy", 10, 0, t0)
	if !f.allow("busy", 10, 120, t0.Add(60*time.Second)) { // 2 cores
		t.Fatal("busy group not exported")
	}
	// a counter reset must not qualify
	if f.allow("reset", 10, 100, t0) || f.allow("reset", 10, 5, t0.Add(time.Minute)) {
		t.Fatal("counter reset qualified")
	}
}

func TestExportFilterDisabled(t *testing.T) {
	if !newExportFilter(0, 0, 0).allow("x", 0, 0, time.Now()) {
		t.Fatal("disabled filter must export everything")
	}
}
