package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	common "github.com/Monitoring-Projects/process-exporter"
	"github.com/Monitoring-Projects/process-exporter/cgroup"
	"github.com/Monitoring-Projects/process-exporter/collector"
	"github.com/Monitoring-Projects/process-exporter/config"
	"github.com/Monitoring-Projects/process-exporter/diagnose"
	"github.com/ncabatoff/fakescraper"
	"github.com/prometheus/client_golang/prometheus"
	verCollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	promVersion "github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
)

// Version is set at build time use ldflags.
var version string

func printManual() {
	fmt.Print(`Usage:
  process-exporter [options] -config.path filename.yml

or 

  process-exporter [options] -procnames name1,...,nameN [-namemapping k1,v1,...,kN,vN]

The recommended option is to use a config file, but for convenience and
backwards compatibility the -procnames/-namemapping options exist as an
alternative.
 
The -children option (default:true) makes it so that any process that otherwise
isn't part of its own group becomes part of the first group found (if any) when
walking the process tree upwards.  In other words, resource usage of
subprocesses is added to their parent's usage unless the subprocess identifies
as a different group name.

Command-line process selection (procnames/namemapping):

  Every process not in the procnames list is ignored.  Otherwise, all processes
  found are reported on as a group based on the process name they share. 
  Here 'process name' refers to the value found in the second field of
  /proc/<pid>/stat, which is truncated at 15 chars.

  The -namemapping option allows assigning a group name based on a combination of
  the process name and command line.  For example, using 

    -namemapping "python2,([^/]+)\.py,java,-jar\s+([^/]+).jar" 

  will make it so that each different python2 and java -jar invocation will be
  tracked with distinct metrics.  Processes whose remapped name is absent from
  the procnames list will be ignored.  Here's an example that I run on my home
  machine (Ubuntu Xenian):

    process-exporter -namemapping "upstart,(--user)" \
      -procnames chromium-browse,bash,prometheus,prombench,gvim,upstart:-user

  Since it appears that upstart --user is the parent process of my X11 session,
  this will make all apps I start count against it, unless they're one of the
  others named explicitly with -procnames.

Config file process selection (filename.yml):

  See README.md.
` + "\n")

}

type (
	prefixRegex struct {
		prefix string
		regex  *regexp.Regexp
	}

	nameMapperRegex struct {
		mapping map[string]*prefixRegex
	}
)

func (nmr *nameMapperRegex) String() string {
	return fmt.Sprintf("%+v", nmr.mapping)
}

// Create a nameMapperRegex based on a string given as the -namemapper argument.
func parseNameMapper(s string) (*nameMapperRegex, error) {
	mapper := make(map[string]*prefixRegex)
	if s == "" {
		return &nameMapperRegex{mapper}, nil
	}

	toks := strings.Split(s, ",")
	if len(toks)%2 == 1 {
		return nil, fmt.Errorf("bad namemapper: odd number of tokens")
	}

	for i, tok := range toks {
		if tok == "" {
			return nil, fmt.Errorf("bad namemapper: token %d is empty", i)
		}
		if i%2 == 1 {
			name, regexstr := toks[i-1], tok
			matchName := name
			prefix := name + ":"

			if r, err := regexp.Compile(regexstr); err != nil {
				return nil, fmt.Errorf("error compiling regexp '%s': %v", regexstr, err)
			} else {
				mapper[matchName] = &prefixRegex{prefix: prefix, regex: r}
			}
		}
	}

	return &nameMapperRegex{mapper}, nil
}

func (nmr *nameMapperRegex) MatchAndName(nacl common.ProcAttributes) (bool, string) {
	if pregex, ok := nmr.mapping[nacl.Name]; ok {
		if pregex == nil {
			return true, nacl.Name
		}
		matches := pregex.regex.FindStringSubmatch(strings.Join(nacl.Cmdline, " "))
		if len(matches) > 1 {
			for _, matchstr := range matches[1:] {
				if matchstr != "" {
					return true, pregex.prefix + matchstr
				}
			}
		}
	}

	return false, ""
}

func readFloat(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v float64
	fmt.Sscan(strings.TrimSpace(string(b)), &v)
	return v
}

// memAvailable returns a function reading MemAvailable (bytes) from the
// procfs of the host, used to turn a memory trend into a time to exhaustion.
func memAvailable(procfs string) func() float64 {
	return func() float64 {
		b, err := os.ReadFile(procfs + "/meminfo")
		if err != nil {
			return 0
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "MemAvailable:") {
				var kb float64
				fmt.Sscanf(strings.TrimPrefix(l, "MemAvailable:"), "%f", &kb)
				return kb * 1024
			}
		}
		return 0
	}
}

func init() {
	promVersion.Version = version
	prometheus.MustRegister(verCollector.NewCollector("process_exporter"))
}

func main() {
	var (
		listenAddress = flag.String("web.listen-address", ":9256",
			"Address on which to expose metrics and web interface.")
		metricsPath = flag.String("web.telemetry-path", "/metrics",
			"Path under which to expose metrics.")
		onceToStdoutDelay = flag.Duration("once-to-stdout-delay", 0,
			"Don't bind, just wait this much time, print the metrics once to stdout, and exit")
		procNames = flag.String("procnames", "",
			"comma-separated list of process names to monitor")
		procfsPath = flag.String("procfs", "/proc",
			"path to read proc data from")
		nameMapping = flag.String("namemapping", "",
			"comma-separated list, alternating process name and capturing regex to apply to cmdline")
		children = flag.Bool("children", true,
			"if a proc is tracked, track with it any children that aren't part of their own group")
		threads = flag.Bool("threads", true,
			"report on per-threadname metrics as well")
		smaps = flag.Bool("gather-smaps", false,
			"gather metrics from smaps_rollup, which contains proportional resident memory size. "+
				"Off by default: reading it pauses the target process in proportion to its size (upstream #246, #360)")
		memBreakdown = flag.Bool("gather-memory-breakdown", false,
			"add anon, file, shmem, data, peak, pagetables and locked to namedprocess_namegroup_memory_bytes (from /proc/pid/status, no smaps)")
		gatherDelay = flag.Bool("gather-delay", false,
			"export namedprocess_namegroup_blkio_delay_seconds_total (time waiting for block IO)")
		gatherLifecycle = flag.Bool("gather-lifecycle", false,
			"export processes_started_total, processes_exited_total and newest_start_time_seconds per group")
		mapsGroups = flag.String("maps.groups", "",
			"regexp of group names whose /proc/pid/maps lines are counted (namedprocess_namegroup_map_count, namedprocess_vm_max_map_count)")
		mapsEvery = flag.Duration("maps.interval", time.Minute, "how often the mappings are counted")
		fdGroups  = flag.String("fd.groups", "",
			"regexp of group names whose open file descriptors are broken down by type (namedprocess_namegroup_open_filedesc_by_type)")
		fdEvery        = flag.Duration("fd.interval", 30*time.Second, "how often the fd types are counted")
		exportMinRSS   = flag.Uint64("export.min-resident-bytes", 0, "export only groups with at least this much resident memory (0: all); see -export.hold")
		exportMinCores = flag.Float64("export.min-cpu-cores", 0, "export only groups using at least this many CPU cores (0: all); see -export.hold")
		exportHold     = flag.Duration("export.hold", 30*time.Minute, "keep exporting a group this long after it last passed the export thresholds")
		reportMissing  = flag.Bool("report-missing", false,
			"with -config.path: report namedprocess_namegroup_num_procs 0 for groups with a static name that never matched")
		cgOn = flag.Bool("cgroup", false,
			"read cgroup v1/v2 data (memory, CPU throttling, pids, pressure) of the processes' cgroups; feeds the diagnose engine and namedprocess_cgroup_*")
		cgRoot   = flag.String("cgroup.root", "/sys/fs/cgroup", "cgroup file system root (in a container the host's, mounted read-only)")
		cgRead   = flag.String("cgroup.read-groups", ".+", "regexp of group names whose cgroups are read")
		cgExpose = flag.String("cgroup.groups", "",
			"regexp of group names for which namedprocess_cgroup_* are always exposed (others only while a diagnose symptom is active)")
		cgHostPSI = flag.Bool("cgroup.host-pressure", true, "with -cgroup: expose /proc/pressure as namedprocess_host_pressure_seconds_total")
		diagOn    = flag.Bool("diagnose", false,
			"sample selected groups over time, correlate the signals and expose symptoms and predictions (namedprocess_diag_*)")
		diagGroups = flag.String("diagnose.groups", ".+",
			"regexp of group names that are analysed in memory")
		diagDetail = flag.String("diagnose.detail-groups", "",
			"regexp of group names for which the detailed diag series (trends, rates, memory breakdown, correlations) are always exposed; other groups expose them only while a symptom is active")
		diagInterval = flag.Duration("diagnose.interval", 15*time.Second,
			"background sampling interval of the analysed groups (0: sample on scrapes only)")
		diagWindow    = flag.Duration("diagnose.window", 30*time.Minute, "fine sample window")
		diagFloorSpan = flag.Duration("diagnose.floor-span", 6*time.Hour, "history kept for trend fits")
		diagBucket    = flag.Duration("diagnose.bucket", 5*time.Minute, "floor bucket size (minimum per bucket removes per-cycle sawtooth)")
		diagMinSpan   = flag.Duration("diagnose.min-span", 2*time.Hour, "minimum observed span before a trend is reported")
		diagHold      = flag.Duration("diagnose.hold", 10*time.Minute, "keep a symptom active this long after it was last detected")
		diagLeakMiB   = flag.Float64("diagnose.leak-min-mib-per-hour", 5, "minimum anonymous RSS floor growth for memory_leak_suspected")
		diagVMMiB     = flag.Float64("diagnose.vm-growth-min-mib-per-hour", 512, "minimum VmData floor growth for address_space_leak")
		diagFDPerHour = flag.Float64("diagnose.fd-min-per-hour", 5, "minimum open fd floor growth for fd_leak")
		diagR2        = flag.Float64("diagnose.r2-min", 0.8, "minimum R2 of a trend fit")
		diagBusy      = flag.Float64("diagnose.busy-loop-cores", 0.9, "minimum steady cpu cores for cpu_busy_loop")
		diagMaps      = flag.String("diagnose.maps-groups", "", "deprecated alias of -maps.groups")
		diagMapsEvery = flag.Duration("diagnose.maps-interval", 0, "deprecated alias of -maps.interval")
		man           = flag.Bool("man", false,
			"print manual")
		configPath = flag.String("config.path", "",
			"path to YAML config file")
		tlsConfigFile = flag.String("web.config.file", "",
			"path to YAML web config file")
		recheck = flag.Bool("recheck", false,
			"recheck process names on each scrape")
		recheckTimeLimit = flag.Duration("recheck-with-time-limit", 0,
			"recheck processes only this much time after their start, but no longer.")
		debug = flag.Bool("debug", false,
			"log debugging information to stdout")
		showVersion = flag.Bool("version", false,
			"print version information and exit")
		removeEmptyGroups = flag.Bool("remove-empty-groups", false, "forget process groups with no processes")
	)
	flag.Parse()

	promlogConfig := &promlog.Config{}
	logger := promlog.New(promlogConfig)

	if *showVersion {
		fmt.Printf("%s\n", promVersion.Print("process-exporter"))
		os.Exit(0)
	}

	if *man {
		printManual()
		return
	}

	var matchnamer common.MatchNamer
	var staticNames []string

	if *configPath != "" {
		if *nameMapping != "" || *procNames != "" {
			log.Fatalf("-config.path cannot be used with -namemapping or -procnames")
		}

		cfg, err := config.ReadFile(*configPath, *debug)
		if err != nil {
			log.Fatalf("error reading config file %q: %v", *configPath, err)
		}
		log.Printf("Reading metrics from %s based on %q", *procfsPath, *configPath)
		matchnamer = cfg.MatchNamers
		staticNames = cfg.StaticNames
		if *debug {
			log.Printf("using config matchnamer: %v", cfg.MatchNamers)
		}
	} else {
		namemapper, err := parseNameMapper(*nameMapping)
		if err != nil {
			log.Fatalf("Error parsing -namemapping argument '%s': %v", *nameMapping, err)
		}

		var names []string
		for _, s := range strings.Split(*procNames, ",") {
			if s != "" {
				if _, ok := namemapper.mapping[s]; !ok {
					namemapper.mapping[s] = nil
				}
				names = append(names, s)
			}
		}

		log.Printf("Reading metrics from %s for procnames: %v", *procfsPath, names)
		if *debug {
			log.Printf("using cmdline matchnamer: %v", namemapper)
		}
		matchnamer = namemapper
	}

	if *recheckTimeLimit != 0 {
		*recheck = true
	}

	var diagEngine *diagnose.Engine
	var mapsRe, fdRe, cgReadRe, cgExposeRe *regexp.Regexp
	var cgReader *cgroup.Reader
	if *cgOn {
		var err error
		if cgReadRe, err = regexp.Compile(*cgRead); err != nil {
			log.Fatalf("bad -cgroup.read-groups: %v", err)
		}
		if *cgExpose != "" {
			if cgExposeRe, err = regexp.Compile(*cgExpose); err != nil {
				log.Fatalf("bad -cgroup.groups: %v", err)
			}
		}
		cgReader = cgroup.NewReader(*cgRoot, *procfsPath)
		if cgReader.Version() == "" {
			log.Printf("cgroup: no cgroup v1 or v2 hierarchy found below %s, cgroup data disabled", *cgRoot)
		} else {
			log.Printf("cgroup %s read from %s", cgReader.Version(), *cgRoot)
		}
	}
	if *mapsGroups == "" {
		*mapsGroups = *diagMaps
	}
	if *diagMapsEvery != 0 {
		*mapsEvery = *diagMapsEvery
	}
	if *mapsGroups != "" {
		var err error
		if mapsRe, err = regexp.Compile(*mapsGroups); err != nil {
			log.Fatalf("bad -maps.groups: %v", err)
		}
	}
	if *fdGroups != "" {
		var err error
		if fdRe, err = regexp.Compile(*fdGroups); err != nil {
			log.Fatalf("bad -fd.groups: %v", err)
		}
	}
	if *diagOn {
		gre, err := regexp.Compile(*diagGroups)
		if err != nil {
			log.Fatalf("bad -diagnose.groups: %v", err)
		}
		var dre *regexp.Regexp
		if *diagDetail != "" {
			if dre, err = regexp.Compile(*diagDetail); err != nil {
				log.Fatalf("bad -diagnose.detail-groups: %v", err)
			}
		}
		dcfg := diagnose.Config{
			Window: *diagWindow, FloorSpan: *diagFloorSpan, Bucket: *diagBucket, MinSpan: *diagMinSpan, Hold: *diagHold,
			R2Min: *diagR2, LeakMinBytesPerHour: *diagLeakMiB * (1 << 20), VMGrowthMinBytesPerHour: *diagVMMiB * (1 << 20),
			FDMinPerHour: *diagFDPerHour, BusyLoopCores: *diagBusy,
			MemAvailable: memAvailable(*procfsPath),
			MaxMapCount:  readFloat(*procfsPath + "/sys/vm/max_map_count"),
		}
		if dre != nil {
			dcfg.DetailAlways = dre.MatchString
		}
		diagEngine = diagnose.New(dcfg, gre)
		log.Printf("diagnose enabled: groups=%q detail=%q interval=%s window=%s floor-span=%s", *diagGroups, *diagDetail, *diagInterval, *diagWindow, *diagFloorSpan)
	}

	pc, err := collector.NewProcessCollector(
		collector.ProcessCollectorOption{
			ProcFSPath:         *procfsPath,
			Children:           *children,
			Threads:            *threads,
			GatherSMaps:        *smaps,
			Namer:              matchnamer,
			Recheck:            *recheck,
			RecheckTimeLimit:   *recheckTimeLimit,
			Debug:              *debug,
			RemoveEmptyGroups:  *removeEmptyGroups,
			Diagnose:           diagEngine,
			DiagnoseInterval:   *diagInterval,
			MapsGroups:         mapsRe,
			MapsInterval:       *mapsEvery,
			MemoryBreakdown:    *memBreakdown,
			GatherDelay:        *gatherDelay,
			GatherLifecycle:    *gatherLifecycle,
			FDGroups:           fdRe,
			FDInterval:         *fdEvery,
			ExportMinResident:  *exportMinRSS,
			ExportMinCores:     *exportMinCores,
			ExportHold:         *exportHold,
			StaticNames:        staticNames,
			ReportMissing:      *reportMissing,
			Cgroup:             cgReader,
			CgroupReadGroups:   cgReadRe,
			CgroupGroups:       cgExposeRe,
			CgroupHostPressure: *cgHostPSI,
		},
	)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}

	prometheus.MustRegister(pc)

	if *onceToStdoutDelay != 0 {
		// We throw away the first result because that first collection primes the pump, and
		// otherwise we won't see our counter metrics.  This is specific to the implementation
		// of NamedProcessCollector.Collect().
		fscraper := fakescraper.NewFakeScraper()
		fscraper.Scrape()
		time.Sleep(*onceToStdoutDelay)
		fmt.Print(fscraper.Scrape())
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	http.Handle(*metricsPath, promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Named Process Exporter</title></head>
			<body>
			<h1>Named Process Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})
	server := &http.Server{Addr: *listenAddress}

	go func() {
		<-sigs
		log.Printf("Shutting down the server\n")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Server Shutdown Failed: %v", err)
		}
	}()

	if err := web.ListenAndServe(server, &web.FlagConfig{
		WebListenAddresses: &[]string{*listenAddress},
		WebConfigFile:      tlsConfigFile,
	}, logger); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start the server: %v", err)
		os.Exit(1)
	}
}
