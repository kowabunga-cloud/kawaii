//go:build linux
// +build linux

/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kawaii

import (
	"net"
	"testing"

	"github.com/kowabunga-cloud/common/agents"
	"github.com/kowabunga-cloud/common/agents/templates"
	"github.com/kowabunga-cloud/common/metadata"
	"github.com/vishvananda/netlink"
)

const (
	TestKawaiiServicesConfigDir = "/tmp/kowabunga/kawaii"
)

var testKawaiiServices = map[string]*agents.ManagedService{
	"nftables": {
		BinaryPath: "",
		UnitName:   "nftables",
		ConfigPaths: []agents.ConfigFile{
			{
				TemplateContent: templates.NftablesFirewallGoTmpl,
				TargetPath:      "firewall.nft",
			},
			{
				TemplateContent: templates.NftablesNatsGoTmpl,
				TargetPath:      "nats.nft",
			},
			{
				TemplateContent: templates.NftablesConfGoTmpl,
				TargetPath:      "nftables.conf",
			},
		},
	},
	"keepalived": {
		BinaryPath: "",
		UnitName:   "keepalived",
		ConfigPaths: []agents.ConfigFile{
			{
				TemplateContent: templates.KeepalivedConfTemplate("kawaii"),
				TargetPath:      "keepalived.conf",
			},
		},
	},
	"strongswan": {
		BinaryPath: "", //TODO: Later use for binary upgrade mgmt
		UnitName:   "strongswan.service",
		User:       "root",
		Group:      "root",
		ConfigPaths: []agents.ConfigFile{
			{
				TemplateContent: templates.IPsecSwanctlConfGoTmpl,
				TargetPath:      "swanctl.conf",
			},
			{
				TemplateContent: templates.IPsecCharonLoggingGoTmpl,
				TargetPath:      "charon-logging.conf",
			},
			{
				TemplateContent: templates.IPsecCharonGoTmpl,
				TargetPath:      "charon.conf",
			},
			{
				TemplateContent: templates.IPsecCharonLogrotateGoTmpl,
				TargetPath:      "charon",
			},
		},
	},
}

var testKawaiiConfig = map[string]any{
	"kawaii": map[string]any{
		"ipsec_connections": []map[string]any{{
			"xfrm_id":                     "1",
			"name":                        "TESTIPSEC",
			"remote_peer":                 "97.8.9.10",
			"remote_subnet":               "10.4.0.0/24",
			"pre_shared_key":              "gibberish",
			"rekey":                       "240",
			"start_action":                "start",
			"dpd_action":                  "restart",
			"dpd_timeout":                 "240s",
			"phase1_lifetime":             "240s",
			"phase1_df_group":             "2",
			"phase1_integrity_algorithm":  "SHA1",
			"phase1_encryption_algorithm": "AES128",
			"phase2_lifetime":             "240s",
			"phase2_df_group":             "2",
			"phase2_integrity_algorithm":  "SHA1",
			"phase2_encryption_algorithm": "AES128",
			"ingress_rules": []map[string]any{{
				"protocol": "tcp",
				"ports":    "443",
				"action":   "allow",
			}}}},
		"public_interface":  "ens3",
		"private_interface": "ens4",
		"peering_interfaces": []string{
			"ens5",
		},
		"vrrp_control_interface": "ens4",
		"public_vip_addresses": []string{
			"60.0.0.1",
			"60.0.0.2",
		},
		"public_gw_address": "60.0.0.254",
		"virtual_ips": []map[string]any{
			{
				"vrrp_id":   1,
				"interface": "ens3",
				"vip":       "60.0.0.1",
				"priority":  150,
				"mask":      28,
				"public":    true,
			},
			{
				"vrrp_id":   2,
				"interface": "ens3",
				"vip":       "60.0.0.2",
				"priority":  150,
				"mask":      28,
				"public":    true,
			},
			{
				"vrrp_id":   2,
				"interface": "ens4",
				"vip":       "10.3.0.1",
				"priority":  150,
				"mask":      25,
				"public":    false,
			},
		},
		"fw_input_default":   "drop",
		"fw_output_default":  "accept",
		"fw_forward_default": "drop",
		"fw_input_extra_networks": []string{
			"10.5.0.0/22",
		},
		"fw_input_rules": []map[string]any{
			{
				"iifname":        "ens3",
				"oifname":        "ens4",
				"source_ip":      "0.0.0.0",
				"destination_ip": "0.0.0.0",
				"direction":      "out",
				"protocol":       "tcp",
				"ports":          "100-150",
				"action":         "forward",
			},
		},
		"fw_output_rules": []map[string]any{
			{
				"iifname":        "ens3",
				"oifname":        "ens4",
				"source_ip":      "0.0.0.0",
				"destination_ip": "0.0.0.0",
				"direction":      "out",
				"protocol":       "tcp",
				"ports":          "100-200",
				"action":         "forward",
			},
		},
		"fw_forward_rules": []map[string]any{
			{
				"iifname":        "ens3",
				"oifname":        "ens4",
				"source_ip":      "0.0.0.0",
				"destination_ip": "0.0.0.0",
				"direction":      "out",
				"protocol":       "tcp",
				"ports":          "100-300",
				"action":         "forward",
			},
		},
		"fw_nat_rules": []map[string]any{
			{
				"private_ip": "10.0.0.0",
				"public_ip":  "70.0.0.0",
				"protocol":   "tcp",
				"ports":      "100-200",
			},
		},
	},
}

func TestKawaiiTemplate(t *testing.T) {
	agents.AgentTestTemplate(t, testKawaiiServices, TestKawaiiServicesConfigDir, testKawaiiConfig)
}

func TestKawaiiSysctlSettings(t *testing.T) {
	keys := map[string]string{}
	for _, s := range kawaiiSysctlSettings {
		keys[s.Key] = s.Value
	}

	cases := []struct{ key, want string }{
		{"net.ipv4.ip_forward", "1"},
		{"net.netfilter.nf_conntrack_max", "524288"},
		{"net.ipv4.conf.all.accept_redirects", "0"},
	}
	for _, c := range cases {
		if keys[c.key] != c.want {
			t.Errorf("sysctl %s: got %q, want %q", c.key, keys[c.key], c.want)
		}
	}
}

func TestKawaiiServicesShape(t *testing.T) {
	for _, name := range []string{"nftables", "keepalived", "strongswan"} {
		svc, ok := kawaiiServices[name]
		if !ok {
			t.Errorf("service %q missing", name)
			continue
		}
		if len(svc.ConfigPaths) == 0 {
			t.Errorf("service %q has no config paths", name)
		}
	}
}

func TestFindPrivateVIPIPsecPeerOwner(t *testing.T) {
	tests := []struct {
		name     string
		ipsec    metadata.KawaiiIPsecConnectionMetadata
		kawaii   metadata.KawaiiMetadata
		expected string // empty string means expect nil
	}{
		{
			name:  "returns private peer VIP for matching VRRP group",
			ipsec: metadata.KawaiiIPsecConnectionMetadata{IP: "60.0.0.1"},
			kawaii: metadata.KawaiiMetadata{
				VirtualIPs: []metadata.VirtualIpMetadata{
					{VRRP: 1, VIP: "60.0.0.1", Public: true},
					{VRRP: 1, VIP: "10.3.0.1", Public: false},
				},
			},
			expected: "10.3.0.1",
		},
		{
			name:  "selects correct peer among multiple VRRP groups",
			ipsec: metadata.KawaiiIPsecConnectionMetadata{IP: "60.0.0.2"},
			kawaii: metadata.KawaiiMetadata{
				VirtualIPs: []metadata.VirtualIpMetadata{
					{VRRP: 1, VIP: "60.0.0.1", Public: true},
					{VRRP: 1, VIP: "10.3.0.1", Public: false},
					{VRRP: 2, VIP: "60.0.0.2", Public: true},
					{VRRP: 2, VIP: "10.3.0.2", Public: false},
				},
			},
			expected: "10.3.0.2",
		},
		{
			name:  "no VIP match returns nil",
			ipsec: metadata.KawaiiIPsecConnectionMetadata{IP: "192.168.1.1"},
			kawaii: metadata.KawaiiMetadata{
				VirtualIPs: []metadata.VirtualIpMetadata{
					{VRRP: 1, VIP: "60.0.0.1", Public: true},
					{VRRP: 1, VIP: "10.3.0.1", Public: false},
				},
			},
			expected: "",
		},
		{
			name:  "sole VIP in group has no peer returns nil",
			ipsec: metadata.KawaiiIPsecConnectionMetadata{IP: "60.0.0.1"},
			kawaii: metadata.KawaiiMetadata{
				VirtualIPs: []metadata.VirtualIpMetadata{
					{VRRP: 1, VIP: "60.0.0.1", Public: true},
				},
			},
			expected: "",
		},
		{
			name:     "empty VirtualIPs returns nil",
			ipsec:    metadata.KawaiiIPsecConnectionMetadata{IP: "60.0.0.1"},
			kawaii:   metadata.KawaiiMetadata{VirtualIPs: nil},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findPrivateVIPIPsecPeerOwner(&tt.ipsec, &tt.kawaii)
			if tt.expected == "" {
				if result != nil {
					t.Errorf("expected nil, got %s", result)
				}
			} else {
				if result == nil {
					t.Fatalf("expected %s, got nil", tt.expected)
				}
				if result.String() != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, result.String())
				}
			}
		})
	}
}

func TestRemoveConflictingRouteIfExistsNoRoutes(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	route := &netlink.Route{Dst: ipNet}
	if err := removeConflictingRouteIfExists(route, []netlink.Route{}); err != nil {
		t.Errorf("unexpected error with empty route list: %v", err)
	}
}

func TestRemoveConflictingRouteIfExistsNoConflict(t *testing.T) {
	_, dst1, _ := net.ParseCIDR("10.1.0.0/24")
	_, dst2, _ := net.ParseCIDR("10.2.0.0/24")
	route := &netlink.Route{Dst: dst1}
	existing := []netlink.Route{{Dst: dst2}}
	if err := removeConflictingRouteIfExists(route, existing); err != nil {
		t.Errorf("unexpected error when no conflict: %v", err)
	}
}
