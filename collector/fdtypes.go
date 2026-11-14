package collector

import (
	"fmt"
	"os"
	"strings"
)

// classifyFD maps the target of a /proc/pid/fd link to a small, fixed set of
// types so the result has bounded cardinality.
func classifyFD(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:"):
		return "socket"
	case strings.HasPrefix(target, "pipe:"):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon_inode"
	case strings.HasPrefix(target, "/dev/infiniband/"):
		return "infiniband"
	case strings.HasPrefix(target, "/dev/shm/"), strings.HasPrefix(target, "/SYSV"):
		return "shm"
	case strings.HasPrefix(target, "/memfd:"):
		return "memfd"
	case strings.HasPrefix(target, "/dev/"):
		return "device"
	case strings.HasPrefix(target, "/proc/"), strings.HasPrefix(target, "/sys/"):
		return "procfs"
	case strings.HasPrefix(target, "/"):
		return "file"
	default:
		return "other"
	}
}

// countFDTypes counts the open file descriptors of the given pids by type.
// Processes that cannot be read (permissions, exited) are skipped.
func countFDTypes(procfs string, pids []int) map[string]int {
	res := map[string]int{}
	for _, pid := range pids {
		dir := fmt.Sprintf("%s/%d/fd", procfs, pid)
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			t, err := os.Readlink(dir + "/" + e.Name())
			if err != nil {
				continue
			}
			res[classifyFD(t)]++
		}
	}
	return res
}
