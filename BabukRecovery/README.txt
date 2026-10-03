Babuk Recovery 3.0.0
====================

This upgrades the production recovery logic in ../tools/babuk_recover.py.
That reference is unchanged. Disk Doctor is unchanged. Read AUDIT.txt for
the complete implementation map and reasons for replacing unsafe behaviors.

Files
-----
babuk_recovery.py       batch/interactive entry point, discovery and reports
recovery_core.py        evidence, diagnosis, plans, gates, transactions/oracles
legacy_readonly.py     verbatim selected production helpers; no legacy mutators
recovery_config.json   documented reference defaults, not a write-gate bypass
AUDIT.txt              preimplementation audit and mutation inventory
tests/test_recovery.py synthetic regression and crash/failure tests
tests/reference_babuk_recover.py.txt  byte-identical quarantined production reference
tests/run_tests.py     test runner producing clean text and JSON evidence
tests/RESULTS.txt      recorded regression output
tests/RESULTS.json     machine-readable test summary
tests/SAFETY_REVIEW.json  reference hashes and final mutation-path review
state/ reports/ transactions/ backups/ checkpoints/ logs/ tests/

Deployment
----------
Keep the complete BabukRecovery directory together. Standard library only,
Python 3.5+ (self-tests require Python 3.8+ because AST regression comparison
uses end_lineno; production modules remain parseable on Python 3.5).
Copy beside the historical tool or to /tmp/BabukRecovery on ESXi. Choose a
persistent --work-dir on a datastore: /tmp does NOT survive host reboot.
Do not overwrite or run the historical repair helper as part of the upgrade.
The project checkout contains the authoritative build and regression reference.
The original D:\forefst source paths were absent; project files were confirmed
as the production reference. The tested package can be copied independently to
D:\forefst\BabukRecovery; no historical production tool is replaced.

Operator workflow
-----------------
1. Read-only discovery/planning:
   python3 babuk_recovery.py --dry-run --root /vmfs/volumes \
     --work-dir /vmfs/volumes/RECOVERY/BabukRecovery --adapter lsilogic

2. Review reports/<run_id>.json and .txt. Confirm source paths, rejected
   candidates, exact planned_hex bytes, current/planned hashes, evidence,
   verification oracles and rollback artifact. The controller option is an
   explicit operator claim; supply the correct controller for the VM.

3. Explicit batch authorization (ESXi only):
   python3 babuk_recovery.py --repair --authorize-repair \
     --source /vmfs/volumes/DS/VM/VM-flat.vmdk.babyk \
     --adapter lsilogic --work-dir /vmfs/volumes/RECOVERY/BabukRecovery

   No mode argument retains interactive per-disk confirmation. EOF stops
   without consent. --analyze is deterministic read-only batch analysis.
   Analysis/dry-run write evidence/report/checkpoint artifacts only; source
   bytes, source names and descriptors are never modified in these modes.

4. Inspect unfinished transactions before any further repair:
   python3 babuk_recovery.py --check-transactions --work-dir WORKDIR

5. Roll back with the recorded ID, in REVERSE transaction order for a disk:
   python3 babuk_recovery.py --rollback TRANSACTION_ID --authorize-rollback \
     --work-dir WORKDIR

6. Display persisted report or run synthetic tests:
   python3 babuk_recovery.py --report --work-dir WORKDIR
   python3 babuk_recovery.py --self-test

Safety and persistent evidence
------------------------------
Each transaction has a random unique ID. original.bin/planned.bin/readback.bin
and verification.json are created exclusively and never reused. SHA-256 backup
readback and rechecking immediately before writing are mandatory. transaction.json
is the immutable initial record. Numbered immutable JSON events are authoritative;
each hashes the preceding record. They are file-fsynced and their directory is
fsynced before the first source mutation. No prior record is overwritten.

PLANNED -> BACKUP_CREATED -> BACKUP_HASH_VERIFIED -> JOURNAL_PREPARED ->
WRITE_STARTED -> WRITE_COMPLETED -> READBACK_VERIFIED -> STRUCTURAL_VERIFIED ->
SEMANTIC_VERIFIED (only if available) -> COMMITTED.

Failures record their classification and rollback requirement. Missing semantic
oracles are UNKNOWN, never SEMANTIC_VERIFIED. A native command's zero exit code
alone cannot establish recovery: exact byte readback and independent structural
checks are also mandatory, followed by whole-plan reanalysis and native chain
verification. Guest boot/Windows OS problems are outside the verified scope.

Filesystem semantics: real NTFS FILE records, sector fixups, attribute/header
bounds, multiple records, unchanged semantic hashes, and MFTMirr consistency
when usable. Missing MFTMirr is reported as unavailable rather than fabricated.
GPT: primary/backup CRCs, array CRCs, reciprocal locations/identity, usable bounds,
partition bounds, unique partition GUIDs, overlap checks and protective MBR.
MBR: bounds, no overlap and exact correspondence to filesystem evidence.
Bootable/active status is UNKNOWN unless independently evidenced; reconstruction
never selects the largest partition as active and never invents a disk signature.

Checkpoint observations retain rejected candidates. Reuse requires matching
canonical path, size, modification metadata, inode/device, selected beginning/
middle/tail/damage-boundary sample hashes and surviving descriptor identity.
--full-hash strengthens this with a whole-source SHA-256 (potentially very slow).
Prewrite gates independently re-read filesystem evidence and semantic record
hashes and validate backup GPT again. Rollback checks identity, size, known current
bytes, neighboring/sampled context and recorded structural evidence ranges.
Cheap sampled fingerprints are change detectors, not proof every unmodified byte
of a multi-terabyte file is intact. No global absence claim follows a limited scan.

Filesystem durability and immutability scope
------------------------------------------
The application never overwrites backup artifacts or journal records. This is
application-level immutability, not hardware WORM or a defense against an
administrator altering/deleting evidence. The hash chain detects damaged earlier
events; it is not a digitally signed forensic attestation. Filesystem/controller
fsync durability guarantees remain a deployment requirement. Production writes
are blocked on Windows; Windows is used for synthetic testing and analysis only.

Unfinished transactions block new repairs. Exact old/new states can be rolled
back, including crashes after a source write but before its completion record.
A pre-backup interruption with unchanged source can be closed without mutation.
Unexpected/torn bytes that match neither expected state block rollback; no force
override silently discards them. Interrupted rename linking both names is
detectable and rollback restores the original namespace. Interrupted scan resumes
at an fsynced window checkpoint only if its source fingerprint still matches.

A real process/power crash may leave state/<source_hash>.lock/owner.json. Its
presence blocks writes. Inspect the journal and owner host/PID before removing
that stale lock directory after establishing the owner is no longer running.
There is intentionally no automatic stale-lock deletion that might release a
live recovery job. VMFS lock state must independently be mode 0 at every write
gate. POSIX advisory locking also prevents cooperating writers. Operators must
keep VMs powered off; no advisory user-space lock can prevent arbitrary external
tools or a VM from being started concurrently. Source r+b failure remains fatal.

Supported and UNKNOWN cases
---------------------------
Supported: understood base-flat VMFS backings, 512-byte disk/NTFS sectors,
unique validated NTFS backups, valid backup GPT reconstruction, evidenced
MBR geometry (up to four primary entries), sector-remainder Babuk trailers,
descriptor creation with explicit controller evidence, safe rollback.

Blocked: sesparse/delta/snapshot topology, snapshot evidence in VM directories,
unknown extent types, non-512 NTFS sectors, extended MBR, >4 MBR partitions,
unrepresentable MBR extents, primary-only GPT requiring backup repair, GPT
extensions (header size other than 92), conflicting primary/backup GPT,
nonunique NTFS geometries, arbitrary unaligned non-Babuk files, active disks,
missing ESXi/native locking, and changed rollback source state.

Renames use exclusive hard-link creation followed by unlink, rather than a
rename primitive that can overwrite an unrelated destination. Some VMFS builds
do not support hardlinks. On such a host rename fails safely with a durable
rollback record; earlier completed transactions remain individually reversible.
This VMFS capability has NOT been validated in this Windows environment.

VMware-native vmkfstools -e is used read-only when present. Its absence or failure
cannot yield HEALTHY_VERIFIED/RECOVERED_VERIFIED for a complete VMware disk.
Descriptor regeneration retains every encrypted descriptor as forensic evidence.
Existing snapshot/parent relationships are never guessed or flattened.
Full-sector multiples of appended trailers cannot be established from a sector
remainder alone; those bytes are not heuristically removed. Unknown filesystems
and absent scanned NTFS records remain UNKNOWN, not a global TOTAL LOSS verdict.
OS bootability, recovered file contents and all unscanned regions remain outside
the semantic verification claim. No live ESXi or actual recovery-media validation
has been performed for this release in this environment.
