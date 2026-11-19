# Security and safe use

This repository contains vulnerability research code and evidence. Use it only in isolated, disposable systems you own or have explicit permission to test.

## Compact PoC safety boundary

The compact `h2c_flow_control_test.py` demonstrates only the HTTP/2 flow-control accounting error on nginx 1.31.8, with nginx 1.31.9 as the patched control. It stops after the one-byte update and PING check. It does not perform memory corruption, heap grooming, disclosure, object reclamation, callback installation, command execution, persistence, or target discovery.

The compact test is validated over cleartext h2c. Its optional TLS path is unvalidated. The full Rapid7 RCE reproduction is a separate, profile-specific public exploit and is not included in this repository.

## Live-run restrictions

- Use only disposable, isolated targets you own or are explicitly authorized to test.
- The compact client accepts only numeric loopback addresses and requires an exact local-lab acknowledgement.
- The Docker differential uses an internal network, no host networking, no published ports, and labeled per-run resources with cleanup.
- Per-command and per-client timeouts are capped at 120 seconds. Target containers have memory, PID, capability, and `no-new-privileges` restrictions.
- No `--cmd`, payload builder, shell, persistence, target enumeration, or automatic exploit chaining is provided.
- Structured evidence is for patch testing and detection research. It is not proof that a remote system is exploitable.

The full `CVE-2026-123007` exploit sends approximately 119.02 GiB of application plaintext and can crash nginx workers. Do not point it at production services, shared infrastructure, public IP addresses, or third-party systems. The unified runner is not a substitute for the upstream exploit's own target checks.

Report security issues in this repository through Censys Research's normal internal disclosure process. Do not open a public issue containing unpublished exploit details or private infrastructure information.
