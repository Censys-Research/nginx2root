# Security and safe use

This repository contains vulnerability research code and evidence. Use it only in isolated, disposable systems you own or have explicit permission to test.

The full `CVE-2026-123007` exploit sends approximately 119.02 GiB of application plaintext and can crash nginx workers. Do not point it at production services, shared infrastructure, public IP addresses, or third-party systems. The unified runner is not a substitute for the upstream exploit's own target checks.

Report security issues in this repository through Censys Research's normal internal disclosure process. Do not open a public issue containing unpublished exploit details or private infrastructure information.
