# KRYPTA-PVIMG/1 — bounded virtual block stream

**Scope:** a working Python io.RawIOBase byte-stream adapter to the independently implemented KRYPTA PVIMG/1 encrypted sector store. This is **not** a mountable filesystem, an OS block device, Windows driver, Android FBE replacement or system-volume encryption.

## Implemented

Source: `research/paged_stream.py` and `research/paged_volume.py`.

- Opens an explicitly selected ordinary `.kpv` file under an exclusive writer lock. Physical disk or partition paths are forbidden.
- Supports seek, tell, read, readinto, write, flush, close, readable, writable and seekable. Also supports Python io.BufferedRandom on top.
- Converts byte-range writes into automatically authenticated encrypted sector transactions, including misaligned writes and writes across paged index boundaries.
- Provides a sparse **1-GiB logical address range**. The physical append-only image has a separate **512-MiB quota**; this does not guarantee a full gigabyte of useful data.
- A single write commits at most **256 touched sectors** atomically at the existing PVIMG API level. Oversized writes are rejected before encryption and without advancing the stream cursor.
- Reads also touch at most 256 sectors per call, including on unaligned offsets. `read(-1)` intentionally returns one bounded chunk rather than allocating the whole gigabyte; callers must handle short reads.
- Returns the latest authenticated commit receipt. A trusted copy outside attacker-controlled storage remains mandatory to detect whole-image rollback.
- Supports explicit stream/volume handle ownership, releasing the lock on close only when ownership was transferred.

## Limits and evidence

A Python stream is not an OS filesystem driver. The adapter cannot encrypt arbitrary writes by Windows/Linux applications until a properly implemented virtual filesystem or block-device interface is added.

Outstanding product gates include scalable performance, production compaction/recovery under real power loss, complete filesystem semantics and ACLs, fuzzing, external anti-rollback authority, hardware-protected keys, PIN enforcement, secure recovery and independent audit.

Tests in `tests/test_paged_stream.py` cover sparse high/low block access, cross-index writes, readinto, buffered I/O, commit failure propagation, bounds, seek correctness, ownership and device-path refusal. Windows/Linux CI runs the test suite across supported Python versions.

**Do not protect irreplaceable information with the development build.** This adapter is an implemented intermediary, not completed full-disk encryption.
