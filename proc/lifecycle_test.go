package proc

import "testing"

// Lifecycle counters: the first Update is the baseline, later new IDs count as
// started, vanished IDs as exited, and block IO delay accumulates monotonically.
func TestLifecycleCounters(t *testing.T) {
	gr := NewGrouper(newNamer("g1"), false, false, false, 0, false, false)
	mk := func(pid int, delay uint64) IDInfo {
		ii := piinfo(pid, "g1", Counts{}, Memory{}, Filedesc{1, 10}, 1)
		ii.Metrics.Ext.BlkIODelayTicks = delay
		return ii
	}
	update := func(infos ...IDInfo) Lifecycle {
		rungroup(t, gr, procInfoIter(infos...))
		return gr.Lifecycle()["g1"]
	}

	if lc := update(mk(1, 500)); lc.Started != 0 || lc.BlkIODelaySeconds != 0 {
		t.Fatalf("baseline update must not count: %+v", lc)
	}
	if lc := update(mk(1, 700), mk(2, 100)); lc.Started != 1 || lc.BlkIODelaySeconds != 3 {
		t.Fatalf("one start and (200+100)/100 s delay expected: %+v", lc)
	}
	lc := update(mk(2, 150))
	if lc.Exited != 1 || lc.Started != 1 || lc.BlkIODelaySeconds != 3.5 {
		t.Fatalf("one exit and 0.5 s more delay expected: %+v", lc)
	}
	if again := update(mk(2, 150)); again != lc {
		t.Fatalf("counters changed without events: %+v vs %+v", again, lc)
	}
}
