# KRYPTA — forensic review of interrupted sector commits

\`research/sealed_sector_review.py\` provides \`inspect_untrusted_roots\`
for encrypted scratch \`.kdevtest\` images. It opens the ordinary file only in
READ-ONLY mode, verifies the public header MAC, authenticates each valid
metadata root and all its live AES-GCM sectors, and reports candidates.

It does **not** return plaintext and does **not** issue a trusted \`receipt\`
or write-authorization token. \`candidate_receipt_UNTRUSTED\` and
\`observed_highest_sequence_UNTRUSTED\` are intentionally marked forensic
observations. A higher valid sequence after a lost acknowledgement is not an
authorized state to begin new writes. Entire-image rollback is still possible
without separately protected historical state; a copied old authentic image
remains cryptographically authentic. The caller must preserve old external
anchors and perform manual offline recovery.

This is not a production disk recovery tool and does not access physical
media, partitions or system disks. Testing uses disposable file-backed
scratch images only.
