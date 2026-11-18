# Reproducing the `CVE-2026-123007` result

Use only an isolated, disposable system you own. The full public exploit sends approximately 119.02 GiB of application plaintext and can crash nginx workers.

## Provenance

The tested exploit is Stephen Fewer / Rapid7's public PoC:

- Repository: https://github.com/sfewer-r7/CVE-2026-123007
- Commit: `ebff45f1b52e70f135fcdb70e3eb334095680fd3`
- Instructions: `NGINX_HTTP2_STANDALONE_REPRODUCTION.md` at that revision

The upstream source is not included in this repository. Follow its own instructions after reviewing its terms.

## Verified environment

The Censys test used:

- Native x86-64 Ubuntu 24.04 on a private research VM.
- Docker CE 29.9.3.
- `avx512f` and `avx512vl` CPU features.
- nginx 1.31.8 image `nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da`.
- CPython 3.10 linked to OpenSSL 3 for the crash trigger.
- A separate CPython 3.10 client environment for the RCE exploit.
- The native streamer rebuilt from the supplied `exploit/streamer.c`.

The CPU checks are necessary but not sufficient: runtime glibc must select the calibrated EVEX/YMM copy routine. The tested profile assumes a fresh or lightly exercised heap, four workers, direct TCP/TLS backpressure, and compatible responses. Auxiliary connections must reach the selected worker. These are constraints of the public exploit, not universal requirements for the vulnerability.

## Build and offline checks

From the upstream handoff root:

```sh
cc -O2 -Wall -Wextra -Werror exploit/streamer.c -lcrypto -o exploit/streamer
./exploit/streamer --version
exploit/.venv/bin/python exploit/exploit.py --help
exploit/.venv/bin/python -m unittest discover -s exploit/tests -t exploit -v
exploit/.venv/bin/python exploit/profiles/profile_tool.py validate \
  exploit/profiles/golden-nginx-1.31.8-debian13-amd64.json
```

The helper must report `nginx-rce-streamer/2`. Create the client environment using the upstream instructions; do not install its dependencies into the system interpreter.

## Fresh target and independent marker

Follow the upstream recipe to start a fresh, unmodified nginx 1.31.8 container with its loopback-only HTTPS listener. Use a new marker name for every attempt. Check that the marker is absent before the attempt, restart the target, and then run the exploit against `127.0.0.1` with the explicit `golden-nginx-1.31.8-debian13-amd64` profile.

After the attempt, independently run `docker exec ... stat -c '%u:%g %a %n' <marker>`. The expected result is UID/GID 101:101, mode 644. Do not accept the client's dispatch message as proof.

## Patched control

Repeat the complete attempt against a fresh, unmodified nginx 1.31.9 target with an otherwise identical configuration and a new marker path. The marker must remain absent. A worker crash or disconnect is not a patched-control result. Save the target version, marker-absence output, client log, and nginx log.

## Verified result

On 18 November 2026, the complete upstream exploit against the isolated 1.31.8 target:

- Sent 119.02 GiB of plaintext over 16 auxiliary connections in 166.04 seconds.
- Captured a 14,393-byte memory disclosure.
- Resolved heap, nginx, and libc addresses.
- Completed controlled reclaim and dispatched a cleanup callback invoking `system(command)`.
- Created `/tmp/rapid7-nginx-h2-proof-01`, independently recorded as UID/GID 101:101, mode 644.

The worker then logged a double free and exited on signal 6. The container remained running with zero restarts and no OOM kill. This is command execution as the nginx worker inside the container, not host root or container escape.

The [archived marker](../evidence/cve-2026-123007/rapid7-rce-marker.txt) and [result note](../evidence/cve-2026-123007/RCE-CONFIRMED.md) preserve this evidence. The unified runner reads that archive without rerunning the exploit or claiming a fresh patched-control check.
