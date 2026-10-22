# KRYPTA: physical sector transport safety gate (P0)

`research/test_sector_transport.py` implements 4096-byte aligned bounded I/O
on a **new, disposable regular .kdevtest file only**. Its purpose is to test the
device-sector contract that will later be needed for actual physical disks.

Implemented: strict device identity and size checks; no symlinks or hardlinks;
single-writer OS lock; bounded sector addressing; explicit flush/fsync;
poisoned handles after ambiguous I/O; no reopening after unexpected resize.
Testing includes short writes, fsync failure, boundary addresses and both
Windows/Linux behavior in CI.

**This is NOT encrypted storage.** Sectors are plaintext synthetic test bytes.
No physical disk path is accepted and it does not touch USB, HDD, SSD or
partitions. This module must not be presented as finished physical disk encryption.

Next acceptance boundary: on-disk encrypted-device format with independent
recoverable key hierarchy, authenticated metadata + data, crash-safe COW commit,
rollback-anchor policy, fixed-layout allocation and rescue. Only after verified
emulated-device fault tests may hardware backend writes be considered.
