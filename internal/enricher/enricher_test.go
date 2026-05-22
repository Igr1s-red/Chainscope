package enricher

import (
	"testing"
)

var cgroups = []struct {
	name    string
	data    string
	wantID  string
	wantRT  string
}{
	{
		name:   "docker",
		data:   "12:blkio:/docker/a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2\n",
		wantID: "a3f2b1c4d5e6",
		wantRT: "docker",
	},
	{
		name:   "containerd cri",
		data:   "0::/system.slice/containerd.service/cri-containerd-b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2a3f2b1c4d5e6f7a8.scope\n",
		wantID: "b9c0d1e2f3a4",
		wantRT: "containerd",
	},
	{
		name:   "podman",
		data:   "0::/machine.slice/libpod-c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2a3f2b1.scope\n",
		wantID: "c4d5e6f7a8b9",
		wantRT: "podman",
	},
	{
		name:   "cri-o",
		data:   "0::/crio-d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2a3f2b1c4.scope\n",
		wantID: "d5e6f7a8b9c0",
		wantRT: "cri-o",
	},
	{
		name:   "kubernetes containerd",
		data:   "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/cri-containerd-e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2a3f2b1c4d5.scope\n",
		wantID: "e6f7a8b9c0d1",
		wantRT: "containerd",
	},
	{
		name:  "host process (no container)",
		data:  "12:blkio:/\n0::/init.scope\n",
		wantID: "",
		wantRT: "",
	},
	{
		name:  "empty cgroup",
		data:  "",
		wantID: "",
		wantRT: "",
	},
}

func TestParseCgroup(t *testing.T) {
	for _, tc := range cgroups {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCgroup(tc.data)
			if got.ContainerID != tc.wantID {
				t.Errorf("ContainerID: got %q, want %q", got.ContainerID, tc.wantID)
			}
			if got.Runtime != tc.wantRT {
				t.Errorf("Runtime: got %q, want %q", got.Runtime, tc.wantRT)
			}
		})
	}
}

func TestParseEnviron(t *testing.T) {
	cases := []struct {
		name       string
		data       string
		wantPod    string
		wantNS     string
	}{
		{
			name:    "k8s pod",
			data:    "PATH=/usr/bin\x00HOSTNAME=my-pod-abc123\x00POD_NAMESPACE=production\x00HOME=/root\x00",
			wantPod: "my-pod-abc123",
			wantNS:  "production",
		},
		{
			name:    "hostname only",
			data:    "HOSTNAME=worker-node\x00PATH=/usr/bin\x00",
			wantPod: "worker-node",
			wantNS:  "",
		},
		{
			name:    "no relevant vars",
			data:    "PATH=/usr/bin\x00HOME=/root\x00",
			wantPod: "",
			wantNS:  "",
		},
		{
			name:    "empty",
			data:    "",
			wantPod: "",
			wantNS:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod, ns := parseEnviron(tc.data)
			if pod != tc.wantPod {
				t.Errorf("PodName: got %q, want %q", pod, tc.wantPod)
			}
			if ns != tc.wantNS {
				t.Errorf("Namespace: got %q, want %q", ns, tc.wantNS)
			}
		})
	}
}
