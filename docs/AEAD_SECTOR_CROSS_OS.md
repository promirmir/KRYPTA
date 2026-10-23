# Cross-platform AEAD sector interoperability

The GitHub workflow \`.github/workflows/aead-sector-cross-os.yml\` moves
the exact same encrypted \`.kdevtest\` scratch image, authenticated external
receipt and throwaway 32-byte CI master key across real hosted Windows and
Linux runners. Both Linux → Windows → Linux and Windows → Linux → Windows
directions are required.

The second OS authenticates the inherited image, commits a new sector and
exports a new receipt; the original OS verifies all committed sector plaintext
hashes against the exact returned bytes.

The artifacts deliberately contain **public synthetic keys only**. Never
place production material in CI artifacts. Passing these tests does not prove
full physical disk encryption, durability against hardware faults, or
pre-boot protection; raw devices are never accessed.
