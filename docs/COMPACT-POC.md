# Compact `CVE-2026-123007` h2c PoC

**One file. No third-party Python packages. No RCE.**

[`h2c_flow_control_test.py`](../h2c_flow_control_test.py) is the Censys compact test behind the 5.69 MB h2c captures. It demonstrates different behavior between vulnerable nginx 1.31.8 and patched 1.31.9 without generating the 60–119 GiB traffic schedules used by Rapid7's later crash and RCE stages.

See the [vulnerable-versus-patched diagram](../docs/CVE-2026-123007-ATTACK-CHAIN.md).

## Run the complete differential

Requirements: Docker with `nginx:1.31.8` and `nginx:1.31.9` images, and Python 3.10 or newer. Use a disposable lab you own.

```sh
uv run python -I h2c_flow_control_test.py \
  --docker --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB
```

The script creates an internal Docker network, starts each target, runs the client in a separate container sharing the target's network namespace, and removes the containers and network afterward. It uses no host networking or published ports. It accepts only numeric loopback targets and requires the exact acknowledgement above.

Expected final result:

```text
PASS: vulnerable h2c accepted over-credit; patched control rejected it
```

The command exits zero only when vulnerable 1.31.8 accepts the one-byte update and returns `POC-SYNC` PING acknowledgment, while patched 1.31.9 rejects the earlier 4 MiB update and closes before the probe.

## What the client does

1. Consumes the connection's initial 65,535-byte window with small responses.
2. Raises the connection window to the HTTP/2 maximum.
3. Requests an 8 MB file and stops reading, leaving response DATA queued.
4. Sends a 4 MiB connection-window update, then resets the response stream.
5. Sends a one-byte update. Vulnerable nginx accepts it after over-crediting.
6. Sends PING. The acknowledgment proves the connection remains alive.

Patched nginx rejects the earlier 4 MiB update and closes with TCP FIN. Its server log records `client violated connection flow control`.

## What it does not do

The compact test does not corrupt memory, reclaim heap objects, install a callback, execute a command, or create a shell. The full RCE implementation is Rapid7's separate public exploit, linked in [`third_party/README.md`](../third_party/README.md).

## TLS status

The client has a `--tls` option for continued testing, but the compact sequence is **not validated over TLS**. Do not describe TLS support as confirmed. The original packet captures are cleartext h2c.

## Run only the offline tests

```sh
uv run pytest tests/test_compact_flow.py
```

These tests cover frame parsing, result classification, and target guards without contacting a target.

## Evidence

The original positive and negative captures are in [`evidence/cve-2026-123007/`](../evidence/cve-2026-123007/). They contain private lab addresses, stock nginx content, and the `POC-SYNC` PING, with no personal information or credentials.
