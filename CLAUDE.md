# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Kawaii** (Kowabunga Adaptive WAn Intelligent Interface) is a Go-based Internet Gateway agent that provides ingress/egress control for the Kowabunga cloud infrastructure platform. It manages firewall (nftables), high-availability (keepalived/VRRP), and VPN (strongSwan/IPsec) services.

## Commands

```bash
make all       # mod + fmt + vet + lint + build
make build     # compile binary to bin/
make tests     # run tests with coverage (outputs coverage.txt)
make fmt       # gofmt
make vet       # go vet
make lint      # golangci-lint
make sec       # gosec security scan
make vuln      # govulncheck
make deb       # build Debian package
make apk       # build Alpine Linux package
make clean     # remove bin/
```

Run a single test:
```bash
go test ./internal/kawaii/... -run TestName -v
```

## Architecture

```
cmd/kawaii/main.go              # Entry point — calls kawaii.Daemonize()
internal/kawaii/
  kawaii.go                     # Core daemon: service definitions, sysctl settings
  kawaii_linux.go               # Linux-specific: XFRM interfaces, routing, VIP ownership
  kawaii_darwin.go              # macOS stubs (for local dev/testing only)
  kawaii_test.go                # Unit tests
```

### How it works

`Daemonize()` calls `agents.KontrollerDaemon()` from `github.com/kowabunga-cloud/common`, which drives the agent lifecycle. The agent manages three system services defined in `kawaiiServices`:

- **nftables** — firewall and NAT rules
- **keepalived** — VRRP for active/standby failover
- **strongswan** — IPsec VPN tunnels

Each service is configured via Go templates (from the common library) and receives instance metadata containing: IPsec tunnel parameters, VIP assignments, network interfaces (public/private/peering), firewall rules, and VRRP settings.

Linux-specific code (`kawaii_linux.go`) handles XFRM interface creation, routing for IPsec tunnels, and VIP ownership detection. The Darwin file provides no-op stubs so the code compiles on macOS.

### Key dependency

`github.com/kowabunga-cloud/common` provides the agent framework, template rendering, and logging. `github.com/vishvananda/netlink` handles Linux netlink operations for network interface and route management.

## Commit Convention

Uses [Conventional Commits](https://www.conventionalcommits.org/) with semantic-release. Types: `feat`, `fix`, `perf`, `chore`, `docs`. Breaking changes trigger major version bumps.

## CI/CD

GitHub Actions workflows: `ci.yml` (build + test on push/PR to master), `sec.yml` (gosec), `vuln.yml` (govulncheck), `release.yml` (automated semantic release).
