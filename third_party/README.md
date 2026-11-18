# Third-party proof of concept

The verified full-chain reproduction used Stephen Fewer / Rapid7's public `CVE-2026-123007` proof of concept:

- Repository: https://github.com/sfewer-r7/CVE-2026-123007
- Tested commit: `ebff45f1b52e70f135fcdb70e3eb334095680fd3`
- Research: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/

The upstream code is **not vendored in this repository**. Its repository contains no license file at the tested revision. Censys does not grant a license to upstream code or imply permission to redistribute it. Review the upstream terms before copying or modifying it.

For the authorized isolated-lab test, the upstream source was used without modification. The native streamer was compiled from its supplied source. See [`../docs/REPRODUCTION.md`](../docs/REPRODUCTION.md) for the Censys validation procedure and results.
