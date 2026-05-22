// Package enricher reads /proc to attribute events to container or host context.
// No BPF struct changes are needed — all enrichment happens in userspace.
package enricher

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ContainerInfo holds container/pod context for a process.
// All fields are empty strings for host (non-containerised) processes.
type ContainerInfo struct {
	ContainerID string // 12-char short ID, e.g. "a3f2b1c4d5e6"
	Runtime     string // "docker", "containerd", "podman", "cri-o", or ""
	PodName     string // Kubernetes pod name (from HOSTNAME env var inside the pod)
	Namespace   string // Kubernetes namespace (from POD_NAMESPACE env var)
}

var (
	dockerRe     = regexp.MustCompile(`/docker/([a-f0-9]{64})`)
	containerdRe = regexp.MustCompile(`cri-containerd-([a-f0-9]{64})`)
	podmanRe     = regexp.MustCompile(`libpod-([a-f0-9]{64})`)
	crioRe       = regexp.MustCompile(`crio-([a-f0-9]{64})`)
	// Generic catch-all for kubelet-managed containers (containerd/cri-o without
	// the provider prefix): last 64-char hex segment at end of a cgroup path line.
	k8sContainerRe = regexp.MustCompile(`/([a-f0-9]{64})(?:\.scope)?$`)
)

// Enrich reads /proc/<pid>/cgroup and /proc/<pid>/environ to determine
// container runtime and Kubernetes pod context. Safe to call concurrently.
func Enrich(pid uint32) ContainerInfo {
	cgroup := readFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if cgroup == "" {
		return ContainerInfo{}
	}
	info := parseCgroup(cgroup)
	if info.ContainerID == "" {
		return ContainerInfo{}
	}
	// Attempt to read pod name / namespace from the container's environment.
	environ := readFile(fmt.Sprintf("/proc/%d/environ", pid))
	if environ != "" {
		info.PodName, info.Namespace = parseEnviron(environ)
	}
	return info
}

func parseCgroup(data string) ContainerInfo {
	for _, line := range strings.Split(data, "\n") {
		if m := dockerRe.FindStringSubmatch(line); m != nil {
			return ContainerInfo{ContainerID: m[1][:12], Runtime: "docker"}
		}
		if m := containerdRe.FindStringSubmatch(line); m != nil {
			return ContainerInfo{ContainerID: m[1][:12], Runtime: "containerd"}
		}
		if m := podmanRe.FindStringSubmatch(line); m != nil {
			return ContainerInfo{ContainerID: m[1][:12], Runtime: "podman"}
		}
		if m := crioRe.FindStringSubmatch(line); m != nil {
			return ContainerInfo{ContainerID: m[1][:12], Runtime: "cri-o"}
		}
	}
	// Generic kubelet path: only match if cgroup path looks like a k8s hierarchy.
	if strings.Contains(data, "kubepods") {
		for _, line := range strings.Split(data, "\n") {
			if m := k8sContainerRe.FindStringSubmatch(line); m != nil {
				// Determine runtime from hierarchy hints.
				rt := "containerd"
				if strings.Contains(line, "crio") {
					rt = "cri-o"
				}
				return ContainerInfo{ContainerID: m[1][:12], Runtime: rt}
			}
		}
	}
	return ContainerInfo{}
}

// parseEnviron extracts HOSTNAME (k8s sets this to pod name) and POD_NAMESPACE.
// /proc/PID/environ is NUL-separated KEY=VALUE pairs.
func parseEnviron(data string) (podName, namespace string) {
	for _, v := range strings.Split(data, "\x00") {
		switch {
		case strings.HasPrefix(v, "HOSTNAME="):
			podName = strings.TrimPrefix(v, "HOSTNAME=")
		case strings.HasPrefix(v, "POD_NAMESPACE="):
			namespace = strings.TrimPrefix(v, "POD_NAMESPACE=")
		}
	}
	return
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
