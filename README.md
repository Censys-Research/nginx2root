# nginx2root lab reproductions

Censys Research reproductions of the five nginx vulnerabilities disclosed in the nginx2root research. All experiments were confined to isolated Docker labs. No Internet or third-party targets were used.

**Release status:** `CVE-2026-123007` has an independently verified command-execution result using Rapid7's public exploit. The other four paths are not presented as working RCE PoCs. The unified runner reports them as not implemented rather than claiming success.

## Results

| CVE | Tested path | Current result |
| --- | --- | --- |
| `CVE-2026-123007` | HTTP/2 flow control | Compact 5.69 MB vulnerable/patched h2c captures. Rapid7's complete RCE chain independently reproduced on a matched native AVX512 profile. |
| `CVE-2026-123633` | HTTP/2 with upstream proxying | UAF and stock worker crash reproduced in the source research; no unified RCE adapter yet. |
| `CVE-2026-123634` | Runtime DNS resolution with subrequests | ASAN UAF and custom-debug crashes reproduced; no stock-image crash or unified RCE adapter yet. |
| `CVE-2026-121810` | HTTP/3 with upstream proxying | Not reproduced. |
| `CVE-2026-113425` | Mail proxy with `auth_http` | UAF and pristine worker crash reproduced in the source research; no unified RCE adapter yet. |

Do not interpret a worker crash, sanitizer report, allocation reuse, or client dispatch message as command execution. RCE requires an independently created command marker with expected ownership and a patched negative control.

## Verified `CVE-2026-123007` result

The complete Rapid7 exploit ran against a fresh isolated nginx 1.31.8 Docker target on native x86-64 AVX512 hardware. It dispatched 119.02 GiB of plaintext over 16 auxiliary connections in 166.04 seconds, captured a 14,393-byte memory disclosure, resolved ASLR, reclaimed the overwritten pool, and dispatched its system-command cleanup callback.

The executed command was:

```sh
touch /tmp/rapid7-nginx-h2-proof-01
```

An independent check recorded the marker as UID/GID 101:101. This demonstrates command execution as the nginx worker inside the container, not host root, an SCTP/kernel exploit, or container escape. A worker subsequently aborted on signal 6 after nginx logged a double free. The result is not a stable persistent shell.

Evidence is in [`evidence/cve-2026-123007/`](evidence/cve-2026-123007/). The [attack-chain diagram](docs/CVE-2026-123007-ATTACK-CHAIN.md) separates the compact accounting test from the full exploit. See [reproduction instructions](docs/REPRODUCTION.md) for the test environment and commands.

## Compact accounting captures

Run the single-file Censys compact accounting PoC with the [Docker instructions](docs/COMPACT-POC.md). It demonstrates the accounting error on nginx 1.31.8 and the patched 1.31.9 control over cleartext h2c. It is not an RCE exploit. TLS support remains under validation and is not claimed.

The two 5.69 MB h2c captures compare nginx 1.31.8 with patched 1.31.9:

- `oracle-v2-positive.pcap`: after queued-DATA cleanup, the vulnerable server accepts `WINDOW_UPDATE(0,1)` while over-credited and answers PING.
- `oracle-v2-negative.pcap`: the patched server rejects `WINDOW_UPDATE(0,4194304)` and closes with TCP FIN. The server log says `client violated connection flow control`; there is no GOAWAY on the wire.

The captures, client results, server logs, and patch analysis together support the accounting conclusion. Packet captures alone do not expose nginx's internal window arithmetic.

## Unified suite

The suite defaults to listing adapters without executing anything. Its archived baseline reads retained evidence and never reruns the 119.02 GiB exploit.

From this directory:

```sh
uv sync
uv run python -m suite list --json
uv run python -m suite verify cve-2026-123007 --json
```

The archived verification returns `archived`, not a fresh verified RCE result. It validates the retained marker and separate patched-control record but does not rerun the exploit or its pre-trigger absence check.

The runner supports explicit, consent-gated live adapters as they are added. Execution requires an exact acknowledgement, loopback targets, per-CVE Docker names and networks, independent marker metadata, and patched-control evidence. Attempts, runtime, and captured output are bounded. Unit tests mock process execution.

```sh
uv run pytest
```

For the profile/heap compatibility matrix on the isolated native AVX512 VM, see [compatibility runner instructions](docs/CVE-2026-123007-COMPATIBILITY.md). It defaults to list/dry-run, includes independent 1.31.9 controls, and has a transport-only mode that never invokes the exploit.

## Third-party PoC and licensing

The full-chain test used Stephen Fewer / Rapid7's public PoC at commit `ebff45f1b52e70f135fcdb70e3eb334095680fd3`. Its source is **not included here** because no license file was present at that revision. See [`third_party/README.md`](third_party/README.md) for the upstream link and scope.

Fresh release validation on 18 November 2026 reproduced command execution on nginx 1.31.8 in 154.46 seconds and confirmed marker absence on a fresh nginx 1.31.9 control. The patched client rejected the profile before the accounting stage. See [validation evidence](evidence/release-validation/VALIDATION.md).

Censys-authored code, documents, and evidence in this repository are licensed under [Apache-2.0](LICENSE). This license does not cover linked upstream code, nginx, Docker images, or other third-party software. Those components retain their respective terms.

## Related research

- [Censys nginx2root research](https://nginx2root.censys.com/)
- [Censys nginx2root advisory](https://censys.com/advisory/nginx2root/)
- [Xint disclosure](https://xint.io/blog/nginx2root-remote-code-execution)
- [nginx security advisories](https://nginx.org/en/security_advisories.html)
