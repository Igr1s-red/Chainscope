// Package policy loads and evaluates the supply-chain allow-list policy.
// Network connections to IPs in known-good registry CIDRs are flagged at
// lower severity; connections to unknown IPs are flagged at higher severity.
package policy

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type Registry struct {
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"`
	CIDRs []string `yaml:"cidrs"`
}

type policyFile struct {
	Registries map[string]Registry `yaml:"registries"`
}

type resolvedRegistry struct {
	name string
	nets []*net.IPNet
}

// Policy is a parsed, lookup-ready allow-list.
type Policy struct {
	registries []resolvedRegistry
}

// Load reads and parses a policy YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	p := &Policy{}
	for id, reg := range pf.Registries {
		rr := resolvedRegistry{name: reg.Name}
		for _, cidr := range reg.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q in registry %q: %w", cidr, id, err)
			}
			rr.nets = append(rr.nets, ipnet)
		}
		p.registries = append(p.registries, rr)
	}
	return p, nil
}

// IsAllowedIP returns (true, registryName) if the IP falls inside any
// known-good registry CIDR, or (false, "") otherwise.
func (p *Policy) IsAllowedIP(ip net.IP) (bool, string) {
	if p == nil {
		return false, ""
	}
	for _, reg := range p.registries {
		for _, n := range reg.nets {
			if n.Contains(ip) {
				return true, reg.name
			}
		}
	}
	return false, ""
}
