# Compact accounting PoC: native AVX512 validation

Date: 18-19 November 2026 (VM timestamps are UTC)

## Verdict

The h2c differential passed against fresh nginx 1.31.8 and 1.31.9 targets on `nginx2root-avx512`. Vulnerable nginx accepted the one-byte update and returned the matching `POC-SYNC` PING ACK (exit 0). Patched nginx closed at the earlier 4 MiB `WINDOW_UPDATE` and logged `client violated connection flow control`; the client exited 1 before the one-byte probe.

**No honest TLS differential was obtained.** TLS remains unvalidated. A vulnerable-only TLS positive is not sufficient evidence.

## Environment and frozen client

- VM: native x86-64 Ubuntu 24.04, Intel Xeon Platinum 8481C with `avx512f` and `avx512vl`.
- Client image: `rapid7-nginx2root-rce-client:3.10`, image ID `23b9297e8bc4`, CPython 3.10.22 and OpenSSL 3.5.7.
- Vulnerable image: local `nginx:1.31.8-rapid7-offline` tagged `nginx:1.31.8`, image ID `793a5e7fb63b`.
- Patched image: `nginx:1.31.9`, image ID `81b01f35f484`.
- Targets used the supplied `lab/nginx-h2c.conf` or `lab/nginx-tls.conf`. Each fresh target passed `nginx -t` and had an 8,388,608-byte `big.bin` before the client ran.
- All client connections used numeric `127.0.0.1`. Direct tests shared the target's network namespace; host-network tests used the loopback-only published port. No external targets were used.
- Final-matrix client SHA-256: `9417718625a82d47315e18149880c3392de1270b73ee04259b71b2ffbe9fbb9c` (local `h2c_flow_control_test.py` at the time of the run). Earlier completed current-client logs used SHA-256 `f1009617355437f3802d6f1f8902093c18a1b065875bfcafaeb575680b1b5feb`.

## Final direct-loopback matrix

Files use the `compact-vm-<transport>-<role>-final-direct-*` prefix. `role` is `vulnerable` for 1.31.8 and `patched` for 1.31.9.

| Transport | Version | Client exit | Observed result |
| --- | --- | ---: | --- |
| h2c | 1.31.8 | 0 | One-byte update accepted; matching PING ACK; accounting error observed |
| h2c | 1.31.9 | 1 | TCP close at `wu4M`; one-byte probe not sent; server logged flow-control rejection |
| TLS | 1.31.8 | 1 | TCP close at `wu4M`; inconclusive, not a vulnerable positive |
| TLS | 1.31.9 | 1 | TCP close at `wu4M`; inconclusive, not a differential |

For direct TLS, both server logs show the same 4 MiB rejection but different effective windows:

- 1.31.8: `window increment 4194304 not allowed for window 2144272383`.
- 1.31.9: `window increment 4194304 not allowed for window 2144313391`.

The 41,008-byte difference is consistent with the patch including queued response bytes in its accounting. It does not complete the required vulnerable positive. On the vulnerable target, the 4 MiB update exceeded the available queued bytes, so the client never reached `RST_STREAM` and the one-byte probe.

## Why the host-network TLS runs do not count

The same frozen-protocol client over Docker's loopback-only published TLS port returned exit 0 on **both** versions. Logs are `compact-vm-tls-*-current-host-*`.

- 1.31.8 accepted the one-byte update and returned PING ACK.
- 1.31.9 also accepted the one-byte update and returned PING ACK, without a flow-control error.

Both responses logged 8,060,805 bytes sent for `big.bin`. The fixed 4 MiB update was accepted because fewer than 4 MiB remained queued. Resetting an already-drained stream does not establish the vulnerability. These are patched-control false positives and invalidate a TLS differential for those conditions.

The earlier `compact-vm-tls-vulnerable-baseline-*` run was a vulnerable-only positive using the older client. It is not promoted to a TLS validation because its matching patched controls did not reject.

## Bounded diagnostics

All diagnostic variants were temporary `/tmp` clients on the VM; they are not part of the public client.

| Experiment | Result |
| --- | --- |
| Direct TLS with original 4 MiB update | Both versions closed at `wu4M`; no vulnerable positive |
| Docker `--network none` TLS | Same direct-loopback outcome on both versions |
| Four-worker `/tmp/rapid7-release-rebuild/nginx.conf` over host network | Both versions returned PING ACK; patched false positive |
| Receive buffer set before TLS handshake | Did not produce a valid differential |
| 64 KiB receive buffer over host network | Both versions returned PING ACK; patched false positive |
| Additional two-second no-read settling interval | Both versions returned PING ACK; patched false positive |
| 2 MiB and 3 MiB intermediate updates | Both versions could return PING ACK; these do not prove over-credit without a queued stream |
| Pre-connect buffer on direct TLS | Both closed at the 4 MiB update |

TLS presents encrypted application writes to the client. nginx's socket/TLS buffering and Docker forwarding change when queued HTTP/2 DATA reaches the kernel and the client. The fixed timing and fixed 4 MiB threshold do not establish the required queue across these paths. h2c exposes the DATA frames directly and reproduced the intended backpressure on direct loopback.

## Exit-code defect and tests

The original client returned `None` (shell exit 0) when the target closed during `fill`, `raise`, `wu4M`, or `rst157`. That incorrectly made a patched rejection look successful. The local client was updated concurrently during this task and now tracks `probe_sent`, rejects pre-probe completion as inconclusive, requires a post-probe PING ACK, checks ALPN, and returns 1 or 2 rather than false success. No further client changes were made for this validation.

Final offline test command:

```sh
uv run pytest investigations/nginx2root-2026-11-18/public-repo/tests/test_compact_flow.py -q
```

Result: `28 passed in 0.13s`.

## Commands used

Copy the current client and supplied configs:

```sh
gcloud compute scp \
  investigations/nginx2root-2026-11-18/public-repo/h2c_flow_control_test.py \
  investigations/nginx2root-2026-11-18/public-repo/run_compact_lab.sh \
  investigations/nginx2root-2026-11-18/public-repo/lab/nginx-h2c.conf \
  investigations/nginx2root-2026-11-18/public-repo/lab/nginx-tls.conf \
  nginx2root-avx512:/tmp/ \
  --project=censys-researcher-playground --zone=us-central1-a --tunnel-through-iap
```

On the VM, the files were arranged as `/tmp/compact-lab/h2c_flow_control_test_final.py`, `/tmp/compact-lab/run_compact_lab.sh`, and `/tmp/compact-lab/lab/nginx-{h2c,tls}.conf`. The final client was made read-only and its SHA-256 checked before the matrix.

For each `VERSION` in `1.31.8 1.31.9`, and `TRANSPORT` in `h2c tls`:

```sh
gcloud compute ssh nginx2root-avx512 \
  --project=censys-researcher-playground --zone=us-central1-a \
  --tunnel-through-iap \
  --command='
    cd /tmp/compact-lab
    NGINX2ROOT_AUTHORIZE_LOCAL_LAB=I-AUTHORIZE-LOCAL-LAB \
      sh ./run_compact_lab.sh VERSION TRANSPORT
    # Poll nginx -t and require stat -c %s big.bin == 8388608.
    sudo docker run --rm \
      --network container:nginx2root-compact-VERSION-TRANSPORT \
      --platform linux/amd64 -v /tmp/compact-lab:/lab:ro \
      rapid7-nginx2root-rce-client:3.10 \
      python3 -I /lab/h2c_flow_control_test_final.py \
      --host 127.0.0.1 --port PORT [TLS_ARG] \
      --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB
  ' --ssh-flag='-o BatchMode=yes' --ssh-flag='-o ConnectTimeout=15'
```

`PORT` and `TLS_ARG` were `80` and empty for h2c, and `443` and `--tls` for TLS. Each target was removed and recreated before the next case. The host-network comparison instead used published port `18443` with `--network host`; all other arguments were unchanged.

The complete launch, target-version, client-exit, client, and nginx logs are retained beside this note. Launch failures and refused non-loopback bridge attempts are retained as diagnostics, not validation results. Compact targets were removed after the final matrix; the pre-existing `nginx2root-release-1319` and `rapid7-nginx-h2-vendor` containers were left untouched.
