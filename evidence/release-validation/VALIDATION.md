# Release validation

Date: 18 November 2026

## Environment

The test used the existing isolated native x86-64 Ubuntu 24.04 VM with `avx512f` and `avx512vl`, Docker CE 29.9.3, and no external targets. The upstream source was pinned to `ebff45f1b52e70f135fcdb70e3eb334095680fd3`. The client used CPython 3.10.22 and OpenSSL 3.5.7. The native helper reported `nginx-rce-streamer/2` and had SHA-256 `cdd28207e285145ef39b114af99b8b2d8d421391cf0d7ed1940bca618aea9623`.

## Offline checks

All 36 upstream component tests passed. The `golden-nginx-1.31.8-debian13-amd64` profile passed validation. The exploit CLI loaded and the native helper reported its expected version.

## Fresh vulnerable target

The fresh nginx 1.31.8 target used the upstream configuration. The client dispatched 119.02 GiB of plaintext in 154.46 seconds. An independent `docker exec stat` returned:

```text
101:101 644 0 /tmp/nginx2root-release-123007-vulnerable
```

This is command execution as the nginx worker inside the container. The client exited zero. The marker is the proof, not the client's dispatch message.

## Fresh patched control

A fresh nginx 1.31.9 target used the same configuration and a different marker. The exploit exited 1 after 0.46 seconds because the in-band HTTP/2 fingerprint matched no profile. It did not reach the accounting stage. An independent `stat` returned exit 1: the marker did not exist.

This control establishes that this public exploit did not execute the command on the patched target. It does not prove that every exploit or every patched configuration fails in the same way.

## Evidence files

- `nginx2root-release-vulnerable-client.log`: full successful client stages.
- `nginx2root-release-vulnerable-marker.txt`: independent marker metadata.
- `nginx2root-release-vulnerable-exit.txt`: client exit status.
- `nginx2root-release-vulnerable-nginx.log`: vulnerable target log.
- `nginx2root-release-patched-client.log`: early profile rejection.
- `nginx2root-release-patched-marker.txt`: marker-absence error from `stat`.
- `nginx2root-release-patched-exit.txt`: patched client exit status.
- `nginx2root-release-patched-nginx.log`: patched target log.
- `patched-control.json`: structured negative-control result.

## Scope

The native streamer was rebuilt from the pinned upstream source in a disposable Ubuntu container with networking disabled. It reported `nginx-rce-streamer/2`. A fresh full exploit run using that rebuilt helper succeeded in 159.84 seconds, and an independent marker check returned:

```text
101:101 644 0 /tmp/rapid7-nginx-h2-release-rebuilt
```

The rebuilt-helper client log and marker are included in this directory. This is command execution as the nginx worker inside the isolated container, not host root or container escape.

The public repository does not contain the upstream exploit source. Users must obtain it from its upstream repository and review its terms. The Censys-authored suite and evidence are covered by this repository's Apache-2.0 license.

The public repository does not contain the upstream exploit source. Users must obtain it from its upstream repository and review its terms. The Censys-authored suite and evidence are covered by this repository's Apache-2.0 license.
