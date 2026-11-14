package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	common "github.com/Monitoring-Projects/process-exporter"
	"github.com/Monitoring-Projects/process-exporter/diagnose"
	"github.com/Monitoring-Projects/process-exporter/proc"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	numprocsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_num_procs",
		"number of processes in this group",
		[]string{"groupname"},
		nil)

	cpuSecsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_cpu_seconds_total",
		"Cpu user usage in seconds",
		[]string{"groupname", "mode"},
		nil)

	readBytesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_read_bytes_total",
		"number of bytes read by this group",
		[]string{"groupname"},
		nil)

	writeBytesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_write_bytes_total",
		"number of bytes written by this group",
		[]string{"groupname"},
		nil)

	majorPageFaultsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_major_page_faults_total",
		"Major page faults",
		[]string{"groupname"},
		nil)

	minorPageFaultsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_minor_page_faults_total",
		"Minor page faults",
		[]string{"groupname"},
		nil)

	contextSwitchesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_context_switches_total",
		"Context switches",
		[]string{"groupname", "ctxswitchtype"},
		nil)

	membytesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_memory_bytes",
		"number of bytes of memory in use",
		[]string{"groupname", "memtype"},
		nil)

	openFDsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_open_filedesc",
		"number of open file descriptors for this group",
		[]string{"groupname"},
		nil)

	worstFDRatioDesc = prometheus.NewDesc(
		"namedprocess_namegroup_worst_fd_ratio",
		"the worst (closest to 1) ratio between open fds and max fds among all procs in this group",
		[]string{"groupname"},
		nil)

	startTimeDesc = prometheus.NewDesc(
		"namedprocess_namegroup_oldest_start_time_seconds",
		"start time in seconds since 1970/01/01 of oldest process in group",
		[]string{"groupname"},
		nil)

	numThreadsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_num_threads",
		"Number of threads",
		[]string{"groupname"},
		nil)

	statesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_states",
		"Number of processes in states Running, Sleeping, Waiting, Zombie, or Other",
		[]string{"groupname", "state"},
		nil)

	mapCountDesc = prometheus.NewDesc(
		"namedprocess_namegroup_map_count",
		"number of memory mappings (lines of /proc/pid/maps), max over the processes of the group",
		[]string{"groupname"},
		nil)

	vmMaxMapCountDesc = prometheus.NewDesc(
		"namedprocess_vm_max_map_count",
		"vm.max_map_count of the host",
		nil,
		nil)

	blkioDelayDesc = prometheus.NewDesc(
		"namedprocess_namegroup_blkio_delay_seconds_total",
		"aggregated block IO delay of the processes of the group (time spent waiting for block IO)",
		[]string{"groupname"},
		nil)

	startedDesc = prometheus.NewDesc(
		"namedprocess_namegroup_processes_started_total",
		"processes of the group started since the exporter began watching",
		[]string{"groupname"},
		nil)

	exitedDesc = prometheus.NewDesc(
		"namedprocess_namegroup_processes_exited_total",
		"processes of the group that exited since the exporter began watching",
		[]string{"groupname"},
		nil)

	newestStartDesc = prometheus.NewDesc(
		"namedprocess_namegroup_newest_start_time_seconds",
		"start time in seconds since 1970/01/01 of the newest process in the group",
		[]string{"groupname"},
		nil)

	fdByTypeDesc = prometheus.NewDesc(
		"namedprocess_namegroup_open_filedesc_by_type",
		"open file descriptors of the selected groups by type (socket, pipe, anon_inode, infiniband, shm, memfd, device, procfs, file, other)",
		[]string{"groupname", "type"},
		nil)

	scrapeErrorsDesc = prometheus.NewDesc(
		"namedprocess_scrape_errors",
		"general scrape errors: no proc metrics collected during a cycle",
		nil,
		nil)

	scrapeProcReadErrorsDesc = prometheus.NewDesc(
		"namedprocess_scrape_procread_errors",
		"incremented each time a proc's metrics collection fails",
		nil,
		nil)

	scrapePartialErrorsDesc = prometheus.NewDesc(
		"namedprocess_scrape_partial_errors",
		"incremented each time a tracked proc's metrics collection fails partially, e.g. unreadable I/O stats",
		nil,
		nil)

	threadWchanDesc = prometheus.NewDesc(
		"namedprocess_namegroup_threads_wchan",
		"Number of threads in this group waiting on each wchan",
		[]string{"groupname", "wchan"},
		nil)

	threadCountDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_count",
		"Number of threads in this group with same threadname",
		[]string{"groupname", "threadname"},
		nil)

	threadCpuSecsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_cpu_seconds_total",
		"Cpu user/system usage in seconds",
		[]string{"groupname", "threadname", "mode"},
		nil)

	threadIoBytesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_io_bytes_total",
		"number of bytes read/written by these threads",
		[]string{"groupname", "threadname", "iomode"},
		nil)

	threadMajorPageFaultsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_major_page_faults_total",
		"Major page faults for these threads",
		[]string{"groupname", "threadname"},
		nil)

	threadMinorPageFaultsDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_minor_page_faults_total",
		"Minor page faults for these threads",
		[]string{"groupname", "threadname"},
		nil)

	threadContextSwitchesDesc = prometheus.NewDesc(
		"namedprocess_namegroup_thread_context_switches_total",
		"Context switches for these threads",
		[]string{"groupname", "threadname", "ctxswitchtype"},
		nil)
)

type (
	scrapeRequest struct {
		results chan<- prometheus.Metric
		done    chan struct{}
	}

	ProcessCollectorOption struct {
		ProcFSPath        string
		Children          bool
		Threads           bool
		GatherSMaps       bool
		Namer             common.MatchNamer
		Recheck           bool
		RecheckTimeLimit  time.Duration
		Debug             bool
		RemoveEmptyGroups bool
		// Diagnose, when non-nil, samples the groups and exposes symptoms.
		Diagnose *diagnose.Engine
		// DiagnoseInterval is the background sampling interval (0: scrape only).
		DiagnoseInterval time.Duration
		// MapsGroups selects groups whose /proc/pid/maps lines are counted.
		MapsGroups   *regexp.Regexp
		MapsInterval time.Duration

		// MemoryBreakdown adds anon, file, shmem, data, peak, pagetables and
		// locked to namedprocess_namegroup_memory_bytes (from /proc/pid/status).
		MemoryBreakdown bool
		// GatherDelay exports the block IO delay counter.
		GatherDelay bool
		// GatherLifecycle exports started/exited counters and the newest start time.
		GatherLifecycle bool
		// FDGroups selects groups whose open file descriptors are broken down by type.
		FDGroups   *regexp.Regexp
		FDInterval time.Duration
		// Export filter: only groups with at least this much resident memory or
		// CPU are exported, plus ExportHold after they last were.
		ExportMinResident uint64
		ExportMinCores    float64
		ExportHold        time.Duration
		// StaticNames are group names known in advance; with ReportMissing a
		// group that never matched is reported with zero processes.
		StaticNames   []string
		ReportMissing bool
	}

	NamedProcessCollector struct {
		scrapeChan chan scrapeRequest
		*proc.Grouper
		threads              bool
		smaps                bool
		source               proc.Source
		scrapeErrors         int
		scrapeProcReadErrors int
		scrapePartialErrors  int
		debug                bool
		diag                 *diagnose.Engine
		diagInterval         time.Duration
		mapsGroups           *regexp.Regexp
		mapsInterval         time.Duration
		mapsLast             time.Time
		mapsCache            map[string]int
		procfs               string

		memBreakdown  bool
		gatherDelay   bool
		lifecycle     bool
		fdGroups      *regexp.Regexp
		fdInterval    time.Duration
		fdLast        time.Time
		fdCache       map[string]map[string]int
		filter        *exportFilter
		staticNames   []string
		reportMissing bool
		maxMapCount   float64
	}
)

func NewProcessCollector(options ProcessCollectorOption) (*NamedProcessCollector, error) {
	fs, err := proc.NewFS(options.ProcFSPath, options.Debug)
	if err != nil {
		return nil, err
	}

	fs.GatherSMaps = options.GatherSMaps
	p := &NamedProcessCollector{
		scrapeChan: make(chan scrapeRequest),
		Grouper:    proc.NewGrouper(options.Namer, options.Children, options.Threads, options.Recheck, options.RecheckTimeLimit, options.Debug, options.RemoveEmptyGroups),
		source:     fs,
		threads:    options.Threads,
		smaps:      options.GatherSMaps,
		debug:      options.Debug,

		diag:         options.Diagnose,
		diagInterval: options.DiagnoseInterval,
		mapsGroups:   options.MapsGroups,
		mapsInterval: options.MapsInterval,
		mapsCache:    map[string]int{},
		procfs:       options.ProcFSPath,

		memBreakdown:  options.MemoryBreakdown,
		gatherDelay:   options.GatherDelay,
		lifecycle:     options.GatherLifecycle,
		fdGroups:      options.FDGroups,
		fdInterval:    options.FDInterval,
		fdCache:       map[string]map[string]int{},
		filter:        newExportFilter(options.ExportMinResident, options.ExportMinCores, options.ExportHold),
		staticNames:   options.StaticNames,
		reportMissing: options.ReportMissing,
	}
	if options.MapsGroups != nil {
		p.maxMapCount = readFloatFile(options.ProcFSPath + "/sys/vm/max_map_count")
	}

	colErrs, _, err := p.Update(p.source.AllProcs())
	if err != nil {
		if options.Debug {
			log.Print(err)
		}
		return nil, err
	}
	p.scrapePartialErrors += colErrs.Partial
	p.scrapeProcReadErrors += colErrs.Read

	go p.start()

	return p, nil
}

// Describe implements prometheus.Collector.
func (p *NamedProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- cpuSecsDesc
	ch <- numprocsDesc
	ch <- readBytesDesc
	ch <- writeBytesDesc
	ch <- membytesDesc
	ch <- openFDsDesc
	ch <- worstFDRatioDesc
	ch <- startTimeDesc
	ch <- majorPageFaultsDesc
	ch <- minorPageFaultsDesc
	ch <- contextSwitchesDesc
	ch <- numThreadsDesc
	ch <- statesDesc
	ch <- scrapeErrorsDesc
	ch <- scrapeProcReadErrorsDesc
	ch <- scrapePartialErrorsDesc
	ch <- threadWchanDesc
	ch <- threadCountDesc
	ch <- threadCpuSecsDesc
	ch <- threadIoBytesDesc
	ch <- threadMajorPageFaultsDesc
	ch <- threadMinorPageFaultsDesc
	ch <- threadContextSwitchesDesc
	ch <- mapCountDesc
	ch <- vmMaxMapCountDesc
	ch <- blkioDelayDesc
	ch <- startedDesc
	ch <- exitedDesc
	ch <- newestStartDesc
	ch <- fdByTypeDesc
	if p.diag != nil {
		p.diag.Describe(ch)
	}
}

// Collect implements prometheus.Collector.
func (p *NamedProcessCollector) Collect(ch chan<- prometheus.Metric) {
	req := scrapeRequest{results: ch, done: make(chan struct{})}
	p.scrapeChan <- req
	<-req.done
}

func (p *NamedProcessCollector) start() {
	var tick <-chan time.Time
	if p.diag != nil && p.diagInterval > 0 {
		t := time.NewTicker(p.diagInterval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case req, ok := <-p.scrapeChan:
			if !ok {
				return
			}
			p.scrape(req.results)
			req.done <- struct{}{}
		case <-tick:
			p.sample()
		}
	}
}

// sample feeds the diagnose engine between scrapes, without emitting metrics.
func (p *NamedProcessCollector) sample() {
	permErrs, groups, err := p.Update(p.source.AllProcs())
	p.scrapePartialErrors += permErrs.Partial
	if err != nil {
		p.scrapeErrors++
		return
	}
	p.observe(groups)
}

func (p *NamedProcessCollector) observe(groups proc.GroupByName) {
	maps := p.maps(groups)
	p.fdTypes()
	if p.diag == nil {
		return
	}
	p.diag.Observe(time.Now(), groups, p.Grouper.Extras(), maps)
}

// fdTypes refreshes the file descriptor type breakdown of the selected groups.
func (p *NamedProcessCollector) fdTypes() {
	if p.fdGroups == nil || time.Since(p.fdLast) < p.fdInterval {
		return
	}
	p.fdLast = time.Now()
	res := map[string]map[string]int{}
	for name, x := range p.Grouper.Extras() {
		if p.fdGroups.MatchString(name) {
			res[name] = countFDTypes(p.procfs, x.Pids)
		}
	}
	p.fdCache = res
}

func readFloatFile(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v float64
	fmt.Sscan(strings.TrimSpace(string(b)), &v)
	return v
}

// maps counts the mappings of the processes of the selected groups. Reading
// /proc/pid/maps takes the target's mmap lock briefly, so it runs at most once
// per interval and only for the selected groups.
func (p *NamedProcessCollector) maps(groups proc.GroupByName) map[string]int {
	if p.mapsGroups == nil {
		return nil
	}
	if time.Since(p.mapsLast) < p.mapsInterval {
		return p.mapsCache
	}
	p.mapsLast = time.Now()
	res := map[string]int{}
	for name, x := range p.Grouper.Extras() {
		if !p.mapsGroups.MatchString(name) {
			continue
		}
		for _, pid := range x.Pids {
			if n := countLines(fmt.Sprintf("%s/%d/maps", p.procfs, pid)); n > res[name] {
				res[name] = n
			}
		}
	}
	p.mapsCache = res
	return res
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}

func utf8(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }

func (p *NamedProcessCollector) scrape(ch chan<- prometheus.Metric) {
	permErrs, groups, err := p.Update(p.source.AllProcs())
	p.scrapePartialErrors += permErrs.Partial
	if err != nil {
		p.scrapeErrors++
		log.Printf("error reading procs: %v", err)
	} else {
		p.observe(groups)
		now := time.Now()
		p.filter.forget(now)
		extras, lifecycle := p.Grouper.Extras(), p.Grouper.Lifecycle()
		for gname, gcounts := range groups {
			if !p.filter.allow(gname, gcounts.Memory.ResidentBytes, gcounts.CPUUserTime+gcounts.CPUSystemTime, now) {
				continue
			}
			rawName := gname
			gname = utf8(gname)
			ch <- prometheus.MustNewConstMetric(numprocsDesc,
				prometheus.GaugeValue, float64(gcounts.Procs), gname)
			ch <- prometheus.MustNewConstMetric(membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.ResidentBytes), gname, "resident")
			ch <- prometheus.MustNewConstMetric(membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.VirtualBytes), gname, "virtual")
			ch <- prometheus.MustNewConstMetric(membytesDesc,
				prometheus.GaugeValue, float64(gcounts.Memory.VmSwapBytes), gname, "swapped")
			if !gcounts.OldestStartTime.IsZero() {
				ch <- prometheus.MustNewConstMetric(startTimeDesc,
					prometheus.GaugeValue, float64(gcounts.OldestStartTime.Unix()), gname)
			}
			ch <- prometheus.MustNewConstMetric(openFDsDesc,
				prometheus.GaugeValue, float64(gcounts.OpenFDs), gname)
			ch <- prometheus.MustNewConstMetric(worstFDRatioDesc,
				prometheus.GaugeValue, float64(gcounts.WorstFDratio), gname)
			ch <- prometheus.MustNewConstMetric(cpuSecsDesc,
				prometheus.CounterValue, gcounts.CPUUserTime, gname, "user")
			ch <- prometheus.MustNewConstMetric(cpuSecsDesc,
				prometheus.CounterValue, gcounts.CPUSystemTime, gname, "system")
			ch <- prometheus.MustNewConstMetric(readBytesDesc,
				prometheus.CounterValue, float64(gcounts.ReadBytes), gname)
			ch <- prometheus.MustNewConstMetric(writeBytesDesc,
				prometheus.CounterValue, float64(gcounts.WriteBytes), gname)
			ch <- prometheus.MustNewConstMetric(majorPageFaultsDesc,
				prometheus.CounterValue, float64(gcounts.MajorPageFaults), gname)
			ch <- prometheus.MustNewConstMetric(minorPageFaultsDesc,
				prometheus.CounterValue, float64(gcounts.MinorPageFaults), gname)
			ch <- prometheus.MustNewConstMetric(contextSwitchesDesc,
				prometheus.CounterValue, float64(gcounts.CtxSwitchVoluntary), gname, "voluntary")
			ch <- prometheus.MustNewConstMetric(contextSwitchesDesc,
				prometheus.CounterValue, float64(gcounts.CtxSwitchNonvoluntary), gname, "nonvoluntary")
			ch <- prometheus.MustNewConstMetric(numThreadsDesc,
				prometheus.GaugeValue, float64(gcounts.NumThreads), gname)
			ch <- prometheus.MustNewConstMetric(statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Running), gname, "Running")
			ch <- prometheus.MustNewConstMetric(statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Sleeping), gname, "Sleeping")
			ch <- prometheus.MustNewConstMetric(statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Waiting), gname, "Waiting")
			ch <- prometheus.MustNewConstMetric(statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Zombie), gname, "Zombie")
			ch <- prometheus.MustNewConstMetric(statesDesc,
				prometheus.GaugeValue, float64(gcounts.States.Other), gname, "Other")

			for wchan, count := range gcounts.Wchans {
				ch <- prometheus.MustNewConstMetric(threadWchanDesc,
					prometheus.GaugeValue, float64(count), gname, utf8(wchan))
			}

			if x, ok := extras[rawName]; ok && p.memBreakdown {
				for _, mt := range []struct {
					name string
					v    uint64
				}{{"anon", x.Ext.RssAnonBytes}, {"file", x.Ext.RssFileBytes}, {"shmem", x.Ext.RssShmemBytes},
					{"data", x.Ext.VmDataBytes}, {"peak", x.Ext.VmHWMBytes}, {"pagetables", x.Ext.VmPTEBytes},
					{"locked", x.Ext.VmLckBytes}} {
					ch <- prometheus.MustNewConstMetric(membytesDesc,
						prometheus.GaugeValue, float64(mt.v), gname, mt.name)
				}
			}
			if p.gatherDelay {
				ch <- prometheus.MustNewConstMetric(blkioDelayDesc,
					prometheus.CounterValue, lifecycle[rawName].BlkIODelaySeconds, gname)
			}
			if p.lifecycle {
				ch <- prometheus.MustNewConstMetric(startedDesc,
					prometheus.CounterValue, float64(lifecycle[rawName].Started), gname)
				ch <- prometheus.MustNewConstMetric(exitedDesc,
					prometheus.CounterValue, float64(lifecycle[rawName].Exited), gname)
				if x, ok := extras[rawName]; ok && !x.NewestStart.IsZero() {
					ch <- prometheus.MustNewConstMetric(newestStartDesc,
						prometheus.GaugeValue, float64(x.NewestStart.Unix()), gname)
				}
			}
			if m, ok := p.mapsCache[rawName]; ok && p.mapsGroups != nil {
				ch <- prometheus.MustNewConstMetric(mapCountDesc, prometheus.GaugeValue, float64(m), gname)
			}
			for typ, n := range p.fdCache[rawName] {
				ch <- prometheus.MustNewConstMetric(fdByTypeDesc, prometheus.GaugeValue, float64(n), gname, typ)
			}

			if p.smaps {
				ch <- prometheus.MustNewConstMetric(membytesDesc,
					prometheus.GaugeValue, float64(gcounts.Memory.ProportionalBytes), gname, "proportionalResident")
				ch <- prometheus.MustNewConstMetric(membytesDesc,
					prometheus.GaugeValue, float64(gcounts.Memory.ProportionalSwapBytes), gname, "proportionalSwapped")
			}

			if p.threads {
				for _, thr := range gcounts.Threads {
					ch <- prometheus.MustNewConstMetric(threadCountDesc,
						prometheus.GaugeValue, float64(thr.NumThreads),
						gname, utf8(thr.Name))
					ch <- prometheus.MustNewConstMetric(threadCpuSecsDesc,
						prometheus.CounterValue, float64(thr.CPUUserTime),
						gname, utf8(thr.Name), "user")
					ch <- prometheus.MustNewConstMetric(threadCpuSecsDesc,
						prometheus.CounterValue, float64(thr.CPUSystemTime),
						gname, utf8(thr.Name), "system")
					ch <- prometheus.MustNewConstMetric(threadIoBytesDesc,
						prometheus.CounterValue, float64(thr.ReadBytes),
						gname, utf8(thr.Name), "read")
					ch <- prometheus.MustNewConstMetric(threadIoBytesDesc,
						prometheus.CounterValue, float64(thr.WriteBytes),
						gname, utf8(thr.Name), "write")
					ch <- prometheus.MustNewConstMetric(threadMajorPageFaultsDesc,
						prometheus.CounterValue, float64(thr.MajorPageFaults),
						gname, utf8(thr.Name))
					ch <- prometheus.MustNewConstMetric(threadMinorPageFaultsDesc,
						prometheus.CounterValue, float64(thr.MinorPageFaults),
						gname, utf8(thr.Name))
					ch <- prometheus.MustNewConstMetric(threadContextSwitchesDesc,
						prometheus.CounterValue, float64(thr.CtxSwitchVoluntary),
						gname, utf8(thr.Name), "voluntary")
					ch <- prometheus.MustNewConstMetric(threadContextSwitchesDesc,
						prometheus.CounterValue, float64(thr.CtxSwitchNonvoluntary),
						gname, utf8(thr.Name), "nonvoluntary")
				}
			}
		}
	}
	if p.mapsGroups != nil && p.maxMapCount > 0 {
		ch <- prometheus.MustNewConstMetric(vmMaxMapCountDesc, prometheus.GaugeValue, p.maxMapCount)
	}
	if p.reportMissing && err == nil {
		for _, n := range p.staticNames {
			if _, ok := groups[n]; !ok {
				ch <- prometheus.MustNewConstMetric(numprocsDesc, prometheus.GaugeValue, 0, utf8(n))
			}
		}
	}
	if p.diag != nil {
		p.diag.Collect(ch)
	}
	ch <- prometheus.MustNewConstMetric(scrapeErrorsDesc,
		prometheus.CounterValue, float64(p.scrapeErrors))
	ch <- prometheus.MustNewConstMetric(scrapeProcReadErrorsDesc,
		prometheus.CounterValue, float64(p.scrapeProcReadErrors))
	ch <- prometheus.MustNewConstMetric(scrapePartialErrorsDesc,
		prometheus.CounterValue, float64(p.scrapePartialErrors))
}
