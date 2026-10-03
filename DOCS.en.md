# Complete operator manual

## Babukafkan v3.0.0

This manual describes the implemented behavior of the new recovery core and every historical utility retained in this repository. Disk Doctor is not part of this release and is unchanged.

[Persian manual](DOCS.md)

[Project introduction](README.md)

[Changes](CHANGELOG.md)

## Scope and recovery model

The observed ransomware variant overwrites 52 × 10 MiB = 520 MiB = 545259520 bytes, then appends a 32-byte trailer. Repeated runs can append multiple trailers. This is knowledge from the studied incident, not a claim that every Babuk variant has identical behavior.

The toolkit repairs evidenced disk structures. It cannot decrypt or recreate overwritten payload bytes. Surviving data, usable disk structure, and a bootable guest OS are separate questions. A valid signature, matching hash, successful command, or discovered filename alone cannot establish complete recovery.

The new implementation lives in `BabukRecovery/`; the historical tools remain in `tools/` unchanged. Their direct mutation paths do not use the new transaction engine.

## Requirements and deployment

- Recovery runtime: Python 3.5+, standard library only.
- Recovery self-tests: Python 3.8+.
- Direct NTFS extraction utility: Python 3.6+.
- Production mutation: identified ESXi host, `vmkfstools`, native free-lock evidence, and `fcntl.flock` support.
- Analysis and synthetic tests can run on Windows. The production write gate blocks Windows.
- Persist evidence on reliable storage outside the target sources, with adequate free space. `/tmp` is not persistent across host reboot.

Copy the complete folder, not only the entry-point script:

```bash
scp -r BabukRecovery root@<esxi-host>:/tmp/
ssh root@<esxi-host>
python3 /tmp/BabukRecovery/babuk_recovery.py --help
```

Run self-tests on a separate suitable machine if the ESXi interpreter is older than Python 3.8. Python 3.5 syntax compatibility is checked, but a live Python 3.5/ESXi runtime has not been validated in this environment.

Keep related VMs powered off and work on an independent source copy. Transaction backups capture changed regions, not the entire disk. No user-space advisory lock can prevent every external tool or another administrator from starting a VM.

## Normal operator workflow

All paths and controller selections below are examples; replace them with verified values. `RECOVERY` must be an existing suitable datastore, separate from the affected sources.

### 1. Read-only discovery

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --analyze \
  --root /vmfs/volumes \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

Discovery deduplicates datastore aliases and groups backing files by VM folder. Folder grouping is an observation, not full proof of disk topology or controller identity. Explicit `--source` values bypass root discovery; give the actual backing extent, not the small descriptor file.

### 2. Exact planning

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --dry-run \
  --source /vmfs/volumes/DS/VM/VM-flat.vmdk.babyk \
  --adapter lsilogic \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

Review every target path, offset, length, original/planned hash, exact planned bytes, provenance, rejection, oracle and rollback artifact. `--adapter` is operator-supplied evidence, not a discovered controller setting.

Read-only modes write reports, analysis state and checkpoints to the work directory. They do not change source bytes, size, names or descriptors. In the current implementation, `--analyze` and `--dry-run` share the same analysis/planning path; no extra scan or executable plan import is implied by the latter.

### 3. Authorized repair

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --repair --authorize-repair \
  --source /vmfs/volumes/DS/VM/VM-flat.vmdk.babyk \
  --adapter lsilogic \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

Repair performs fresh analysis. It does not execute an old JSON report as a plan. Authorization cannot bypass source stability, evidence, environment, backup or verification gates.

Repeat `--source` for batch processing. Sources are deduplicated and sorted. Each source has its own verdict; inspect per-source results rather than treating a mixed overall verdict as one disk's outcome.

Without a mode argument, the program analyzes and asks per actionable disk. `y` authorizes that disk, `n` skips, and `q` stops. EOF is never consent. The new entry point does not implement the historical repair-all response.

### 4. Review and extract

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --report \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

`--report` displays the last persisted report; it does not revalidate the source. Run fresh analysis for current state. After successful namespace restoration, use the renamed clean backing path.

Direct extraction, mounting, guest boot and OS repair are separate steps. Mounting or running guest repair utilities may create mutations outside this transaction history. A verified disk-structure verdict does not guarantee application-level content integrity or OS bootability.

## Complete recovery CLI reference

Modes are mutually exclusive.

| Option | Implemented behavior |
|---|---|
| `--analyze` | Deterministic read-only batch analysis and planning. |
| `--dry-run` | Exact read-only planning through the same analysis path. |
| `--repair` | Execute freshly analyzed eligible actions; requires `--authorize-repair`. |
| `--rollback ID` | Roll back one transaction; requires `--authorize-rollback`. |
| `--check-transactions` | Inspect incomplete/invalid journals, without mutation or automatic rollback. |
| `--report` | Display `state/latest_run.json`, without rescan. |
| `--self-test` | Run synthetic fixtures; no production source required. |
| No mode | Interactive per-disk analysis and confirmation. |

| Shared option | Meaning/default |
|---|---|
| `--source PATH` | Repeatable actual backing extent; bypasses root discovery. |
| `--root PATH` | Discovery root; defaults to `/vmfs/volumes`. Used only without explicit sources. |
| `--work-dir PATH` | Persistent evidence/state location; defaults to entry-point directory. Set explicitly in production. |
| `--tail MIB` | Tail search window; nonnegative; defaults to 2048 MiB. |
| `--full-hash` | Adds a full source SHA-256 to the fingerprint; costly on large files and repeated verification. |
| `--adapter VALUE` | `lsilogic`, `buslogic`, `ide`, or `pvscsi`; no guessed default for creating a missing descriptor. |
| `--authorize-repair` | Explicit repair authorization; does not override gates. |
| `--authorize-rollback` | Explicit rollback authorization; does not override unexpected source state. |
| `-h`, `--help` | Actual argument reference. |

No `--force`, `--skip-env`, `--apply`, language selector, or report-plan import exists in the new entry point. CLI messages currently use English.

Exit codes: `0` for acceptable analyzed/recovered states, successful display/rollback, or no unfinished journals; `2` for blocked/partial/failed results, invalid arguments or unfinished journals; `130` for operator interruption. An analysis exit code of zero can mean recoverable, not repaired. Unhandled I/O errors may also terminate the interpreter nonzero.

## Architecture and write gate

```text
DiskState → Evidence → Candidate → Diagnosis → RepairPlan
                                             ↓
                                          WriteGate
                                             ↓
                                         Transaction
                                             ↓
                                         Verification
```

Ordinary explicit classes retain the original Python 3.5 runtime floor. Discovery and scan observations cannot invoke legacy repair helpers. Every planned action specifies the object, range, original/planned bytes and hashes, provenance, verification method and rollback artifact.

Before mutation, the implementation rechecks the source fingerprint and native lock state, independently re-reads filesystem evidence and previously recorded semantic hashes, validates backup GPT again where applicable, verifies exact current bytes and confirms artifact hashes. Missing, inferred, historical-only or conflicting replacement evidence blocks writes.

MBR reconstruction never marks the largest partition active or invents a disk signature. Unknown active state is recorded separately; geometry can be restored with inactive entries for data accessibility. More than four primary MBR partitions, extended partitions or unrepresentable extents are blocked rather than silently truncated.

Descriptor creation is limited to understood flat-base VMFS extents and explicit controller evidence. Sparse headers, snapshot/delta naming, neighboring chain evidence and unknown relationships block guessing. Encrypted descriptors remain as evidence.

Safe rename uses exclusive hardlink creation then unlink, preventing replacement of an unrelated destination. Some VMFS versions may not support this. Failure is journaled; earlier completed transactions are independently reversible. An interruption between link/unlink can leave both names and is covered by synthetic rollback tests. Actual VMFS capability remains unvalidated here.

## Transactions and immutable artifacts

```text
PLANNED → BACKUP_CREATED → BACKUP_HASH_VERIFIED → JOURNAL_PREPARED
→ WRITE_STARTED → WRITE_COMPLETED → READBACK_VERIFIED
→ STRUCTURAL_VERIFIED → SEMANTIC_VERIFIED (only when available) → COMMITTED
```

Failure states include `FAILED_PREWRITE`, `FAILED_WRITE`, `FAILED_READBACK`, `FAILED_STRUCTURAL_VERIFY`, `FAILED_SEMANTIC_VERIFY` and `ROLLBACK_REQUIRED`. Successful rollback records `ROLLED_BACK` then `ROLLED_BACK_VERIFIED`.

```text
WORKDIR/transactions/<transaction_id>/
  transaction.json
  0000_PLANNED.json
  0001_BACKUP_CREATED.json
  ...
  original.bin
  planned.bin
  readback.bin
  verification.json
```

`transaction.json` is an immutable initial snapshot. Numbered, chained, immutable events are authoritative for latest state. Each event hashes its predecessor. Files and the containing directory are fsynced before the source mutation. No previous event or transaction backup is reused or overwritten.

Backups are independently hashed and read back, then rechecked immediately before writing. Exact mutated bytes are read independently after write. Failed readback hashes and failed structural/semantic results are retained. New-file creation can have an empty original artifact: absence is the original state; creation length and backup length are separately recorded.

Application-level immutability is not hardware WORM, a signed forensic attestation or protection against an administrator altering/deleting files. Storage/controller fsync guarantees and reliable evidence retention remain deployment responsibilities. A byte-exact committed transaction with an unavailable semantic oracle does not automatically yield a whole-disk verified result.

## Evidence and independent checks

Evidence classes: `PRIMARY_SURVIVOR`, `BACKUP_SURVIVOR`, `STRUCTURAL_REDUNDANCY`, `HISTORICAL_METADATA`, `INFERRED`, `OPERATOR_SUPPLIED`, `UNKNOWN`.

Provenance and conclusion state are distinct. Candidates currently use `HYPOTHESIS`, `VERIFIED` and `REJECTED`; actual mutation lifecycle is in the journal. An inferred value is not silently promoted to verified evidence. Rejected alternatives remain in reports. The same failed action with unchanged source and planned bytes is not automatically retried; relevant changed variables are recorded for a different attempt.

### Level 1: exact readback

The exact replacement range must equal planned bytes. Truncation checks the expected size. Rename checks source identity/content, with full-hash comparison when requested. This establishes byte/namespace integrity, not meaning.

### Level 2: structure

- **NTFS:** signature, BPB, partition offset, geometry/extent bounds, backup/primary relationship, actual record size, USA sector fixups, bounded record headers/attributes, at least four valid records out of the first eight, and MFTMirr consistency when usable.
- **GPT:** primary/backup header CRC, partition-array CRC, reciprocal locations and identity, usable-LBA bounds, partition extents, unique partition GUIDs, no overlaps and protective MBR. Unknown header extensions are blocked; supported header size is 92 bytes.
- **MBR:** signature, valid entry bounds, no invalid overlap, exact relation to independently evidenced filesystem extents and no invented active entry during reconstruction.
- **Descriptor:** bounded parse, supported single VMFS flat extent, exact sector count, existing backing, base-disk parent identity and no unknown chain relationship.

A missing/unusable MFTMirr is reported unavailable. A usable inconsistent mirror blocks repair. Checking FILE signatures alone is insufficient; the new verifier inspects real record structures.

### Level 3: semantics

The NTFS oracle reads actual records and checks usable mirror consistency. VMware's independent read-only chain command is used when available:

```bash
vmkfstools -e /vmfs/volumes/DS/VM/VM.vmdk
```

Zero exit status alone is insufficient: byte readback and structural checks must also pass. Missing native chain validation prevents a complete VMware disk's `HEALTHY_VERIFIED`/`RECOVERED_VERIFIED` verdict. Bootability, every file's content and application-level integrity remain outside the structural recovery claim.

### Stale metadata and ambiguity

A plausible historical backup may describe an earlier larger filesystem. Smaller size alone does not select it. Surviving primary evidence, an independently validated partition table or another independent filesystem must resolve the conflict. Multiple plausible remaining geometries block writes. No-hit conclusions are scoped to the tested regions.

## Persistent state, reports and progress

The work directory contains `state/`, `reports/`, `transactions/`, `backups/`, `checkpoints/`, `logs/`, `tests/`. Actual transaction bytes reside inside each transaction folder, not necessarily in the generic `backups/` folder.

Run reports have unique JSON/text filenames and a concise log. `state/latest_run.json` and current analysis/checkpoint files are atomically replaced; historical run reports and transaction events are not. Reports include environment and host details, source fingerprints, observed folder relationships, evidence/candidates, rejected alternatives, diagnosis, exact plan, applicable transactions, verification and verdicts. Write-specific fields appear only on relevant execution paths.

Sample fingerprints include canonical path, size, modification metadata, inode/device, beginning/middle/tail/damage-boundary samples and existing descriptor identity. Optional full hash strengthens change detection. Sample equality is not proof that every unsampled byte is unchanged. Independent prewrite evidence checks and rollback structural/context samples add protection.

NTFS scanning covers the first up to 2 GiB and the configured tail, merging overlaps. It uses 8 MiB windows with short overlap and persisted checkpoints. Long scans show current item/region, bytes, MiB/s, elapsed time, ETA and checkpoint path. Short operations avoid noisy progress. Full-hash computation currently has no separate granular progress meter. Finished phases print `DONE/CHECKED`.

### Result states

| State | Meaning within the implemented scope |
|---|---|
| `HEALTHY_VERIFIED` | No required mutations, mandatory structure/semantic checks and independent native VMware validation passed. Not a whole-file-content/boot guarantee. |
| `DAMAGED_RECOVERABLE` | An evidenced plan exists; production environment capability is not established. |
| `WRITE_READY_VERIFIED` | Evidenced plan and environment capability established; final authorization, backup and execution-time rechecks remain. |
| `RECOVERED_VERIFIED` | Transactions committed and whole-plan final analysis reached the healthy verified result. |
| `BLOCKED_INSUFFICIENT_EVIDENCE` | Mandatory evidence missing. |
| `BLOCKED_CONFLICTING_EVIDENCE` | Source/evidence/reconstruction conflicts. |
| `BLOCKED_UNSUPPORTED_LAYOUT` | Unsupported disk/partition layout. |
| `BLOCKED_UNSUPPORTED_VMDK_LAYOUT` | Unknown sparse/snapshot/parent semantics. |
| `BLOCKED_SOURCE_IN_USE` | Source not independently proven free. |
| `FAILED_ENVIRONMENT_GATE` | Mandatory operational environment missing. |
| `FAILED_TRANSACTION` | Transaction or required history failed/incomplete. |
| `RECOVERY_PARTIAL` | Complete verification unavailable or mixed source outcomes; not necessarily additional damage. |

Failure classifications include environment/source changes/use, insufficient/conflicting evidence, unsupported layout, backup/journal/write/readback failures, structural/semantic verification failures and rollback failures. `ROLLBACK_SOURCE_STATE_CHANGED` prevents overwriting unexpected bytes.

## Interruption, scan resumption and rollback

Re-run the same scan command with the same work directory. Checkpoints are reused only for the same fingerprint and search regions. A changed source invalidates observations. Scan resumption is not automatic write roll-forward.

Inspect unfinished transactions:

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py --check-transactions \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

A real crash can leave `state/<source_hash>.lock/owner.json`. Inspect the recorded owner host/PID, verify the process is gone and inspect journals before manually removing a stale lock directory. Automatic stale-lock removal is intentionally absent; deleting live locks/history is not a recovery procedure.

Rollback uses recorded IDs, **in reverse chronological order for each disk**:

```bash
python3 /tmp/BabukRecovery/babuk_recovery.py \
  --rollback <32-character-transaction-id> --authorize-rollback \
  --work-dir /vmfs/volumes/RECOVERY/BabukRecovery
```

It validates fixed in-transaction artifacts, backup hash/length, recorded coordinates, inode/device/size compatibility, neighboring/selected structural context, and exact current bytes against original or known planned state. Unexpected/torn bytes that match neither known state block rollback. No force override is implemented.

Restored bytes must read back to the original SHA-256. Creation rollback checks absence; rename rollback checks identity/content. A pre-backup interruption with unchanged original state can be closed without mutation. Rollback failure evidence is appended. Old reusable `.bak` files/manifests are not automatically imported or guessed into new transactions.

## File inventory and migration

| File | Role |
|---|---|
| `BabukRecovery/babuk_recovery.py` | CLI, discovery, authorization, source results/reports. |
| `BabukRecovery/recovery_core.py` | State/evidence/planning/gates, fingerprints, transactions, rollback and oracles. |
| `BabukRecovery/legacy_readonly.py` | Selected verbatim original readers/builders; excludes original mutation helpers and unconditional main. |
| `BabukRecovery/recovery_config.json` | Documented reference defaults. Not loaded as runtime configuration; CLI is authoritative. |
| `BabukRecovery/README.txt` | Portable technical operations guide. |
| `BabukRecovery/AUDIT.txt` | Original implementation map, mutation inventory and replacement rationale. |
| `BabukRecovery/tests/test_recovery.py` | Synthetic regression suite. |
| `BabukRecovery/tests/run_tests.py` | Writes clean text/JSON test results. |
| `BabukRecovery/tests/reference_babuk_recover.py.txt` | Quarantined historical reference for regression; not an operational script. |
| `BabukRecovery/tests/RESULTS.txt`, `RESULTS.json` | Recorded test run, not a promise for another deployment. |
| `BabukRecovery/tests/SAFETY_REVIEW.json` | Original-reference hashes and final mutation-path audit from the recorded environment. |
| `BabukRecovery/.gitignore`, directory `.gitkeep` files | Exclude runtime evidence while retaining folder skeleton. |
| `README.md`, `DOCS.md`, `DOCS.en.md`, `CHANGELOG.md` | Introduction, complete manuals and change history. |
| `releases/v3.0.0.md` | Release description and validation limits. |
| `.github/workflows/recovery-tests.yml` | Synthetic CI; no access to recovery media. |

The original production file remains `tools/babuk_recover.py`. Deploy the complete new folder separately. Do not migrate old flag names or assume old manifests provide new transaction guarantees. Run existing repaired sources through read-only analysis first; already evidenced healthy sources should have no mutation plan.

Recorded raw hashes are from their original environment; line-ending conversion in a checkout can alter byte hashes without changing code. Compare evidence with its stated capture environment. Do not publish customer paths, source backups, operational state or transaction bytes to a public repository.

## Every supplementary tool

### `tools/deep_probe.py`: read-only forensic profile

Measures entropy/observed damage, inspects partition structures and filesystem signatures, and checks actual MFT signature reads. It also recognizes Linux filesystem/LVM/swap signatures. Default scanning covers selected regions; **only `--full` requests a whole-disk signature sweep**.

```bash
python3 tools/deep_probe.py IMAGE
python3 tools/deep_probe.py IMAGE --full
python3 tools/deep_probe.py --all /vmfs/volumes
```

It never mutates the source. Live-source reads may be inconsistent and impose I/O load. Historical FILE-signature checks are weaker than the new core's record validation; old emphatic messages are not complete semantic proof.

### `tools/gpt_info.py`: backup GPT inspection

```bash
python3 tools/gpt_info.py IMAGE
```

Displays backup header/partition offsets, sizes and names using a sector-aligned logical endpoint. It does not physically trim the source. This historical reader lacks the full CRC/reciprocity checks and can guess the array location. Treat output as supplemental observation, not write authorization.

### `tools/babuk_mft.py`: direct NTFS listing/extraction

Requires a readable primary boot sector at the supplied **byte offset**. Sample offsets/record numbers below are placeholders, not values to infer from filename or size.

```bash
python3 tools/babuk_mft.py info IMAGE 1048576
python3 tools/babuk_mft.py find IMAGE 1048576 invoice --max 60
python3 tools/babuk_mft.py ad IMAGE 1048576
python3 tools/babuk_mft.py dump IMAGE 1048576 /recovery-output/inventory.csv
python3 tools/babuk_mft.py extract IMAGE 1048576 42 /recovery-output/recovered.bin
```

- `info`: boot/MFT geometry and survival observations.
- `find`: case-insensitive filename substring search; default limit 60.
- `ad`: locate Active Directory-related database/log/SYSTEM files and report damage overlap.
- `dump`: one-pass inventory of paths, sizes, extents and damage overlap to CSV.
- `extract`: read one file using its MFT record reference into a separate destination.

Source operations are read-only, but CSV/extraction destinations are written with overwrite behavior. Never choose the source as destination. Historical extraction zero-pads short reads, reports damage overlap and extracts the unnamed DATA stream; it does not guarantee all alternate streams, compression/encryption modes or intact application content. Validate the resulting payload independently.

### `tools/refs_veeam.py`: raw ReFS/Veeam investigation

Finds UTF-16 backup filenames and structural signatures, inspects bytes and decodes surviving boot records. A filename hit does not establish a complete valid backup chain. The new automatic recovery core does not repair ReFS.

```bash
python3 tools/refs_veeam.py names IMAGE --out /recovery-output/names.txt
python3 tools/refs_veeam.py names IMAGE --start 1099511627776 --end 2199023255552 --window 64 --quiet
python3 tools/refs_veeam.py refs IMAGE --start 545259520
python3 tools/refs_veeam.py around IMAGE OFFSET_BYTES
python3 tools/refs_veeam.py vbr IMAGE OFFSET_BYTES
```

`names`, `refs`, `around` and `vbr` do not mutate source bytes. `--out` writes/overwrites a text destination. `--start` and `--end` are byte offsets; `--window` is MiB, default 64. `--quiet` reduces name-scan progress, not every command's entire output.

Historical metadata-replacement previews:

```bash
python3 tools/refs_veeam.py restore IMAGE BACKUP_OFFSET_BYTES \
  --to PARTITION_START_BYTES --part-size PARTITION_SIZE_BYTES
python3 tools/refs_veeam.py supb IMAGE BACKUP_OFFSET_BYTES \
  --to PRIMARY_OFFSET_BYTES --size 65536
```

Adding `--apply` enables the old direct write path. `restore` copies a 512-byte boot sector; `supb` copies the specified region, default 65536 bytes. Their reusable `.refs-vbr.bak`/`.refs-supb.bak` files and signature-oriented verification are **not** the new journal-first engine. Do not use them on original recovery media merely because a signature looks valid; historical checkpoint semantics require separate expert evaluation on an independent copy.

### `tools/babuk_recover.py`: original guided recovery

Retained unchanged as the field-experience/regression reference. It includes environment checks, datastore/disks, per-VM grouping, NTFS discovery, proposed trailer/boot/table/descriptor repairs, interactive consent and legacy manifest rollback. Use the new core for supported operational repairs.

```bash
python3 tools/babuk_recover.py --help
```

Historical options: `--root`, `--log`, `--tail`, `--adapter`, `--skip-env`. Its docstring mentions `--restore`, but the actual parser has no dedicated execution branch for it; this manual does not promise it. Legacy result names/backup files are not new verified states/transactions. Old unsafe active selection, sparse-descriptor assumptions and after-write journaling remain in the quarantined reference and are never invoked by the new implementation.

### `tools/rebuild_mbr.py`: legacy standalone MBR helper

```bash
python3 tools/rebuild_mbr.py IMAGE
```

Default is a preview. `--apply` enables direct sector-0 write and `--boot N` selects an active entry. It rejects an unaligned source but defaults to activating partition 1, keeps only the first four entries and writes a reusable `.mbr.bak`. Those historical behaviors are not the new engine's safety model; describing the tool is not recommending it as a gate bypass.

## Self-tests and CI

```bash
python3 BabukRecovery/babuk_recovery.py --self-test
python3 BabukRecovery/tests/run_tests.py
```

The second command writes `tests/RESULTS.txt` and `RESULTS.json`. Tests use temporary synthetic fixtures only. One fixture has about 540 MiB logical size to compare actual behavior beyond the 520 MiB boundary; physical allocation depends on the test filesystem's sparse-file behavior.

75 recorded tests cover trailers, NTFS primary/backup/MFT/mirror validity, stale and ambiguous geometry, GPT CRC/reconstruction/conflicts/overlap, MBR/active flags, sparse/snapshot rejection, flat descriptors, interrupted transactions, backup/journal/write/readback/structural/semantic failures, source use/changes, checkpoint resumption, safe rollback and repeated execution. Python 3.5 syntax is checked for production modules.

CI uses only synthetic fixtures on hosted Windows/Linux with the declared Python matrix. A configured matrix is not a completed test result until its runs pass. No live ESXi compatibility, VMFS hardlink capability or real recovery payload is tested by CI.

## Troubleshooting and unsupported cases

- **Descriptor blocked:** confirm actual backing type, snapshot/chain evidence and independently known controller; a flat filename alone does not establish parent semantics.
- **Source in use:** all native lock observations must establish mode 0. Missing/unreadable lock state is unknown, not free.
- **Rename failure:** destination collision or missing hardlink support can stop the action after earlier individual transactions; inspect journal and rollback in reverse order.
- **No NTFS found:** inspect tested regions. Limited scan absence is not whole-disk absence or total-loss proof. A supplementary full scan adds observations, not authorization.
- **Valid-looking backup rejected:** inspect stale geometry, extent bounds, table conflicts, neighboring volumes and actual record checks.
- **Source changed:** cached observations cannot be reused. Stabilize the source and analyze again.
- **Rollback blocked:** preserve unexpected bytes and artifacts. No blind force restore is implemented.
- **Guest does not boot:** recovery scope is disk structures, not automatic OS repair, VM registration or power operations.
- **Extracted file rejected by its application:** inspect damaged extents, zero-padded reads, stream limitations and actual format/content rather than output-file existence.

Supported automatic writes: understood flat VMFS base, 512-byte disk/NTFS sectors, unique evidenced NTFS geometry, validated backup GPT reconstruction, representable up-to-four primary MBR entries and understood base descriptors.

Blocked/unknown: sparse/snapshot/delta layouts, unknown parents, non-512 NTFS sectors, extended MBR, >4 primary entries, unrepresentable geometry, primary-only GPT requiring backup repair, unknown header extensions, ambiguous/stale unresolved candidates, non-Babuk arbitrary unaligned files, sector-multiple trailers without evidence, unexpected rollback bytes and automatic repair of other filesystems.

Independent native validation, actual ESXi deployment, storage durability, guest boot and complete recovered file content require separate environment-specific verification.
