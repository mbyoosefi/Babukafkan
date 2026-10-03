"""Journal-first recovery core. Python 3.5+, standard library only.

Explicit objects use ordinary classes to preserve the production ESXi Python
3.5 floor. This module never mounts a filesystem or starts a virtual machine.
"""
import binascii
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager

import legacy_readonly as legacy

VERSION = '3.0.0'
SECTOR = 512
DAMAGE = legacy.DAMAGE
EVIDENCE_CLASSES = ('PRIMARY_SURVIVOR', 'BACKUP_SURVIVOR',
                    'STRUCTURAL_REDUNDANCY', 'HISTORICAL_METADATA',
                    'INFERRED', 'OPERATOR_SUPPLIED', 'UNKNOWN')
RESULT_STATES = ('HEALTHY_VERIFIED', 'DAMAGED_RECOVERABLE', 'WRITE_READY_VERIFIED',
                 'RECOVERED_VERIFIED', 'BLOCKED_INSUFFICIENT_EVIDENCE',
                 'BLOCKED_CONFLICTING_EVIDENCE', 'BLOCKED_UNSUPPORTED_LAYOUT',
                 'BLOCKED_UNSUPPORTED_VMDK_LAYOUT', 'BLOCKED_SOURCE_IN_USE',
                 'FAILED_ENVIRONMENT_GATE', 'FAILED_TRANSACTION', 'RECOVERY_PARTIAL')


class RecoveryError(Exception):
    def __init__(self, classification, message):
        self.classification = classification
        super(RecoveryError, self).__init__(classification + ': ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def timestamp():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def read_at(path, off, length):
    if off < 0 or length < 0:
        raise RecoveryError('INSUFFICIENT_EVIDENCE', 'negative range')
    with open(path, 'rb') as handle:
        handle.seek(off)
        data = handle.read(length)
    if len(data) != length:
        raise RecoveryError('INSUFFICIENT_EVIDENCE', 'short read at %d' % off)
    return data


def sync_dir(path):
    # Windows does not expose directory fsync through the stdlib. Writes are
    # blocked there by production preflight; fixtures still verify file fsync.
    if os.name == 'nt':
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def immutable(path, data):
    with open(path, 'xb') as handle:
        if handle.write(data) != len(data):
            raise RecoveryError('BACKUP_FAILURE', 'short artifact write')
        handle.flush()
        os.fsync(handle.fileno())
    sync_dir(os.path.dirname(path))
    if read_at(path, 0, len(data)) != data:
        raise RecoveryError('BACKUP_FAILURE', 'artifact readback mismatch')


def json_bytes(value):
    return json.dumps(value, sort_keys=True, indent=2).encode('utf-8') + b'\n'


def atomic_json(path, value):
    temporary = path + '.' + uuid.uuid4().hex + '.tmp'
    immutable(temporary, json_bytes(value))
    os.replace(temporary, path)
    sync_dir(os.path.dirname(path))


def load_json(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def fingerprint(path, full=False):
    path = os.path.realpath(path)
    before = os.stat(path)
    if not stat.S_ISREG(before.st_mode):
        raise RecoveryError('UNSUPPORTED_LAYOUT', 'regular backing file required')
    length = before.st_size
    window = min(length, 65536)
    offsets = sorted(set((0, max(0, length // 2 - window // 2),
                          max(0, length - window),
                          min(max(0, length - window), DAMAGE))))
    value = dict(path=path, size=length, device=before.st_dev, inode=before.st_ino,
                 mtime_ns=getattr(before, 'st_mtime_ns', before.st_mtime),
                 samples=[dict(offset=o, length=window,
                               sha256=sha(read_at(path, o, window))) for o in offsets])
    if full:
        value['full_sha256'] = file_hash(path)
    desc = descriptor_path(path)
    if desc and os.path.exists(desc):
        if os.path.getsize(desc) > 1024 * 1024:
            value['descriptor_identity'] = 'OVERSIZED_UNSUPPORTED'
        else:
            value['descriptor_identity'] = dict(path=desc, sha256=file_hash(desc))
    after = os.stat(path)
    if (after.st_size, after.st_mtime, after.st_ctime, after.st_ino, after.st_dev) != (
            before.st_size, before.st_mtime, before.st_ctime, before.st_ino, before.st_dev):
        raise RecoveryError('SOURCE_CHANGED', 'source changed during fingerprint')
    return value


class DiskState(object):
    def __init__(self, path, full=False):
        self.path = os.path.realpath(path)
        self.fingerprint = fingerprint(self.path, full)
        self.size = self.fingerprint['size']
        self.data_end = self.size - self.size % SECTOR


class Evidence(object):
    def __init__(self, evidence_class, description, scope, state='VERIFIED'):
        if evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(evidence_class)
        self.evidence_class = evidence_class
        self.description = description
        self.scope = scope
        self.state = state

    def to_dict(self):
        return vars(self).copy()


class Candidate(object):
    def __init__(self, start, size, sector_offset, bpb, evidence, checks):
        self.start, self.size = start, size
        self.sector_offset, self.bpb = sector_offset, bpb
        self.evidence, self.checks = evidence, checks
        self.state = 'HYPOTHESIS'
        self.reason = ''

    def to_dict(self):
        value = vars(self).copy()
        value['evidence'] = self.evidence.to_dict()
        return value


class Diagnosis(object):
    def __init__(self):
        self.candidates = []
        self.rejected = []
        self.evidence = []
        self.blockers = []
        self.partitions = []
        self.table = None

    def to_dict(self):
        return dict(candidates=[c.to_dict() for c in self.candidates],
                    rejected_candidates=[c.to_dict() for c in self.rejected],
                    evidence=[e.to_dict() for e in self.evidence],
                    blockers=self.blockers, partitions=self.partitions, table=self.table)


class RepairPlan(object):
    def __init__(self, disk):
        self.disk = disk
        self.actions = []
        self.blockers = []
        self.verdict = 'BLOCKED_INSUFFICIENT_EVIDENCE'

    def add(self, operation, offset, old, planned, evidence, oracle, reason,
            context=None, path=None, destination=None):
        path = path or self.disk.path
        action = dict(source_path=path, operation_type=operation, offset=offset,
                      length=len(planned) if operation == 'CREATE' else len(old),
                      backup_length=len(old), planned_length=len(planned),
                      sha256_before=sha(old), sha256_planned=sha(planned),
                      planned_hex=planned.hex(), evidence_class=evidence.evidence_class,
                      evidence_description=evidence.description, evidence=evidence.to_dict(),
                      reason=reason, structural_oracle=oracle,
                      semantic_oracle='NTFS_RECORDS' if oracle in ('NTFS', 'MBR', 'GPT')
                      else 'VMWARE_NATIVE' if oracle == 'DESCRIPTOR' else 'NOT_APPLICABLE',
                      context=context or {}, destination=destination,
                      source_fingerprint=self.disk.fingerprint,
                      rollback_artifact='transactions/<transaction_id>/original.bin')
        if operation == 'CREATE':
            action['object_fingerprint'] = None
        else:
            action['object_fingerprint'] = fingerprint(path)
        self.actions.append(action)

    def to_dict(self):
        return dict(source_path=self.disk.path, source_fingerprint=self.disk.fingerprint,
                    actions=self.actions, blockers=self.blockers, final_verdict=self.verdict,
                    write_gate_evaluation=getattr(self, 'gate_evaluation', {}))


def command(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=30)
        return dict(available=True, returncode=result.returncode,
                    output=result.stdout.decode('utf-8', 'replace'))
    except (OSError, subprocess.TimeoutExpired) as error:
        return dict(available=False, returncode=None, output=str(error))


def preflight():
    native = shutil.which('vmkfstools')
    version = command(['vmware', '-v'])
    try:
        import fcntl
        advisory_lock = hasattr(fcntl, 'flock')
    except ImportError:
        advisory_lock = False
    return dict(hostname=socket.gethostname(), python=sys.version,
                esxi=version, vmkfstools=native, platform=sys.platform,
                directory_fsync=os.name != 'nt',
                write_capable=(os.name != 'nt' and version['returncode'] == 0
                               and 'ESXi' in version['output'] and bool(native) and advisory_lock),
                advisory_lock=advisory_lock,
                optional_oracles=dict(vmware_chain=bool(native)))


def source_use(path, environment):
    if not environment.get('write_capable'):
        raise RecoveryError('ENVIRONMENT', 'ESXi/native locking unavailable; analysis only')
    result = command([environment['vmkfstools'], '-D', path])
    # Every reported VMFS lock must explicitly be mode 0; absence is UNKNOWN.
    modes = re.findall(r'\bmode\s+(\d+)\b', result['output'])
    if result['returncode'] != 0 or not modes or any(m != '0' for m in modes):
        raise RecoveryError('SOURCE_IN_USE', 'VMFS lock not independently proven free')
    return result


class WriteGate(object):
    def __init__(self, environment=None, use_probe=None):
        self.environment = environment if environment is not None else preflight()
        self.use_probe = use_probe or source_use

    def check(self, action, expected_fingerprint, authorization=False):
        if not authorization:
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'explicit write authorization required')
        ev = action.get('evidence', {})
        if ev.get('state') != 'VERIFIED' or ev.get('evidence_class') in (
                'INFERRED', 'UNKNOWN', 'HISTORICAL_METADATA'):
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'replacement evidence not verified')
        if not action.get('structural_oracle') or not action.get('semantic_oracle'):
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'verification oracle missing')
        if action['structural_oracle'] not in ('NTFS', 'MBR', 'GPT', 'ALIGNMENT', 'IDENTITY', 'DESCRIPTOR'):
            raise RecoveryError('UNSUPPORTED_LAYOUT', 'unsupported verification oracle')
        if action['operation_type'] not in ('PATCH', 'TRUNCATE', 'CREATE', 'RENAME'):
            raise RecoveryError('UNSUPPORTED_LAYOUT', 'unsupported operation')
        if action['offset'] < 0 or action['length'] < 0:
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'invalid mutation range')
        contexts = ([action['context']] if action['structural_oracle'] == 'NTFS' else
                    action['context'].get('volumes', []))
        for value in contexts:
            candidate = from_context(value)
            check = ntfs_checks(expected_fingerprint['path'], candidate)
            if not check['ok']:
                raise RecoveryError('INSUFFICIENT_EVIDENCE', 'filesystem evidence changed before write')
            original_semantic = value.get('checks', {}).get('semantic', {}).get('details')
            if original_semantic and check['semantic']['details'] != original_semantic:
                raise RecoveryError('SOURCE_CHANGED', 'MFT evidence changed since diagnosis')
        if fingerprint(expected_fingerprint['path'], 'full_sha256' in expected_fingerprint) != expected_fingerprint:
            raise RecoveryError('SOURCE_CHANGED', 'diagnosis fingerprint differs')
        self.use_probe(expected_fingerprint['path'], self.environment)
        path = action['source_path']
        if action['operation_type'] == 'CREATE':
            if os.path.lexists(path):
                raise RecoveryError('SOURCE_CHANGED', 'creation target already exists')
        else:
            if path != expected_fingerprint['path']:
                raise RecoveryError('SOURCE_CHANGED', 'mutation path differs from locked object')
            if read_at(path, action['offset'], action['length']) != bytes.fromhex(action['old_hex']):
                raise RecoveryError('SOURCE_CHANGED', 'current mutation bytes differ')
        if action['destination'] and os.path.lexists(action['destination']):
            raise RecoveryError('SOURCE_CHANGED', 'rename destination exists')
        if action['operation_type'] == 'PATCH' and len(bytes.fromhex(action['planned_hex'])) != action['length']:
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'patch length differs from backed-up range')
        if action['operation_type'] == 'TRUNCATE' and action['offset'] + action['length'] != expected_fingerprint['size']:
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'truncation does not cover exact tail')
        if action['structural_oracle'] == 'GPT' and not gpt_read(expected_fingerprint['path'], action['context']['data_end']):
            raise RecoveryError('INSUFFICIENT_EVIDENCE', 'backup GPT evidence changed before write')


@contextmanager
def source_lock(path, workspace):
    lock_id = sha(os.path.realpath(path).encode('utf-8'))
    directory = os.path.join(workspace, 'state', lock_id + '.lock')
    try:
        os.mkdir(directory)
    except FileExistsError:
        raise RecoveryError('SOURCE_IN_USE', 'recovery lock exists; inspect stale lock manually')
    handle = None
    try:
        immutable(os.path.join(directory, 'owner.json'), json_bytes(dict(pid=os.getpid(),
                   host=socket.gethostname(), path=path, timestamp=timestamp())))
        if os.name != 'nt':
            import fcntl
            handle = open(path, 'rb')
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RecoveryError('SOURCE_IN_USE', str(error))
        yield
    finally:
        if handle:
            handle.close()
        owner = os.path.join(directory, 'owner.json')
        if os.path.exists(owner):
            os.unlink(owner)
        os.rmdir(directory)


class Workspace(object):
    def __init__(self, path):
        self.path = os.path.realpath(path)
        for name in ('state', 'reports', 'transactions', 'backups', 'checkpoints', 'logs', 'tests'):
            os.makedirs(os.path.join(self.path, name), exist_ok=True)

    def incomplete(self, path=None):
        out = []
        for name in sorted(os.listdir(os.path.join(self.path, 'transactions'))):
            folder = os.path.join(self.path, 'transactions', name)
            if not os.path.isdir(folder):
                continue
            try:
                record = load_transaction(folder)
            except Exception as error:
                out.append(dict(transaction_id=name, transaction_state='UNKNOWN', error=str(error)))
                continue
            if path and record['source_fingerprint']['path'] != os.path.realpath(path):
                continue
            if record['transaction_state'] not in ('COMMITTED', 'ROLLED_BACK_VERIFIED',
                                                    'FAILED_PREWRITE'):
                out.append(record)
        return out


def parse_ntfs(sector):
    bpb = legacy.parse_bpb(sector)
    if not bpb or sector[510:512] != b'\x55\xaa' or sector[0] not in (0xEB, 0xE9):
        return None
    code = struct.unpack_from('<b', sector, 64)[0]
    record_size = (1 << -code) if -20 <= code < 0 else code * bpb['cluster']
    if record_size < bpb['bps'] or record_size > 65536 or record_size % bpb['bps']:
        return None
    if bpb['mft'] * bpb['cluster'] + 4 * record_size > bpb['vol_bytes']:
        return None
    if bpb['mirr'] * bpb['cluster'] + record_size > bpb['vol_bytes']:
        return None
    bpb['record_size'] = record_size
    bpb['hidden'] = struct.unpack_from('<I', sector, 28)[0]
    return bpb


def file_record(record, sector_size):
    """Independent NTFS FILE oracle: USA fixups, headers, bounded attributes."""
    if len(record) < 48 or record[:4] != b'FILE':
        return None
    usa, count = struct.unpack_from('<HH', record, 4)
    attr, flags, used, allocated = struct.unpack_from('<HHII', record, 20)
    if count != len(record) // sector_size + 1 or usa < 8 or usa + count * 2 > attr:
        return None
    if not (48 <= attr < used <= allocated == len(record)) or not flags & 1:
        return None
    fixed = bytearray(record)
    tag = record[usa:usa + 2]
    for i in range(1, count):
        off = i * sector_size - 2
        if record[off:off + 2] != tag:
            return None
        fixed[off:off + 2] = record[usa + i * 2:usa + i * 2 + 2]
    pos, attrs = attr, 0
    while pos + 4 <= used:
        kind = struct.unpack_from('<I', fixed, pos)[0]
        if kind == 0xFFFFFFFF:
            return bytes(fixed) if attrs else None
        if pos + 16 > used:
            return None
        length = struct.unpack_from('<I', fixed, pos + 4)[0]
        nonresident = fixed[pos + 8]
        if kind == 0 or kind > 0x100 or length < (64 if nonresident else 24) or length % 8 or pos + length > used:
            return None
        if nonresident not in (0, 1):
            return None
        if not nonresident:
            value_len, value_off = struct.unpack_from('<IH', fixed, pos + 16)
            if value_off < 24 or value_off + value_len > length:
                return None
        else:
            run_off = struct.unpack_from('<H', fixed, pos + 32)[0]
            if not 64 <= run_off < length:
                return None
        attrs += 1
        pos += length
    return None


def ntfs_records(path, start, bpb):
    size = bpb['record_size']
    off = start + bpb['mft'] * bpb['cluster']
    records, hashes = [], []
    for i in range(8):
        if off + (i + 1) * size > start + bpb['vol_bytes']:
            break
        record = file_record(read_at(path, off + i * size, size), bpb['bps'])
        records.append(record)
        hashes.append(sha(record) if record else None)
    mirror_off = start + bpb['mirr'] * bpb['cluster']
    mirror = file_record(read_at(path, mirror_off, size), bpb['bps'])
    mirror_consistent = None if mirror is None else bool(records and records[0] == mirror)
    return dict(valid_records=sum(r is not None for r in records), record_hashes=hashes,
                mft_offset=off, mirror_consistent=mirror_consistent)


def ntfs_checks(path, candidate, require_primary=False):
    bpb = candidate.bpb
    start, size = candidate.start, candidate.size
    end = os.path.getsize(path) // SECTOR * SECTOR
    checks = dict(bounds=0 < start and start + size <= end,
                  partition_offset=(bpb['hidden'] == start // bpb['bps']),
                  supported_sector_size=bpb['bps'] == 512,
                  signature=True)
    if not all(checks.values()):
        return dict(ok=False, checks=checks, semantic=dict(available=False))
    sector = read_at(path, candidate.sector_offset, 512)
    checks['source_sector_matches_geometry'] = parse_ntfs(sector) == bpb
    if require_primary:
        primary = read_at(path, start, 512)
        checks['primary_matches'] = primary == sector and parse_ntfs(primary) == bpb
    semantic = ntfs_records(path, start, bpb)
    checks['mft_records'] = semantic['valid_records'] >= 4
    checks['mirror_consistency'] = semantic['mirror_consistent'] is not False
    backup = read_at(path, start + bpb['total'] * bpb['bps'], 512)
    checks['backup_relationship'] = backup == sector
    return dict(ok=all(checks.values()), checks=checks,
                semantic=dict(available=True, ok=checks['mft_records'] and checks['mirror_consistency'],
                              details=semantic))


def crc(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def partitions_valid(parts, size, floor=512):
    previous = floor
    for part in sorted(parts, key=lambda p: p['off']):
        if part['off'] < previous or part['size'] <= 0 or (part['off'] + part['size']) > size:
            return False
        if part['off'] % 512 or part['size'] % 512:
            return False
        previous = part['off'] + part['size']
    return True


def gpt_read(path, end, primary=False):
    where = 1 if primary else end // 512 - 1
    try:
        raw = read_at(path, where * 512, 512)
        if raw[:8] != b'EFI PART':
            return None
        revision, header_size, checksum, reserved = struct.unpack_from('<IIII', raw, 8)
        current, alternate, first, last = struct.unpack_from('<QQQQ', raw, 24)
        array_lba, num, esz, array_crc = struct.unpack_from('<QIII', raw, 72)
        last_lba = end // 512 - 1
        if revision != 0x10000 or reserved or header_size != 92:
            return None  # unknown extensions must not be dropped during rebuild
        if current != where or alternate != (last_lba if primary else 1):
            return None
        if not (0 < num <= 512 and 128 <= esz <= 4096 and esz % 128 == 0):
            return None
        length = num * esz
        array_sectors = (length + 511) // 512
        if not (2 + array_sectors <= first <= last < last_lba - array_sectors):
            return None
        if primary and not (2 <= array_lba and array_lba + array_sectors <= first):
            return None
        if not primary and not (last < array_lba and array_lba + array_sectors <= last_lba):
            return None
        zero = bytearray(raw[:header_size])
        zero[16:20] = b'\0' * 4
        if crc(zero) != checksum:
            return None
        array = read_at(path, array_lba * 512, length)
        if crc(array) != array_crc:
            return None
        parts = []
        for i in range(num):
            entry = array[i * esz:(i + 1) * esz]
            if entry[:16] == b'\0' * 16:
                continue
            start, stop = struct.unpack_from('<QQ', entry, 32)
            if not first <= start <= stop <= last or entry[16:32] == b'\0' * 16:
                return None
            parts.append(dict(off=start * 512, size=(stop - start + 1) * 512,
                              guid=entry[16:32].hex(), type_guid=entry[:16].hex()))
        if not partitions_valid(parts, end) or len({p['guid'] for p in parts}) != len(parts):
            return None
        return dict(raw=raw.hex(), array=array.hex(), partitions=parts,
                    header=dict(revision=revision, first_usable=first, last_usable=last,
                                disk_guid=raw[56:72].hex(), num=num, esz=esz,
                                entries_lba=array_lba))
    except (OSError, RecoveryError, struct.error):
        return None


def verify_gpt(path, end):
    primary, backup = gpt_read(path, end, True), gpt_read(path, end)
    keys = ('revision', 'first_usable', 'last_usable', 'disk_guid', 'num', 'esz')
    reciprocal = bool(primary and backup and primary['array'] == backup['array'] and
                      all(primary['header'][k] == backup['header'][k] for k in keys))
    mbr = read_at(path, 0, 512)
    protective = (mbr[510:512] == b'\x55\xaa' and mbr[450] == 0xEE and
                  struct.unpack_from('<I', mbr, 454)[0] == 1 and
                  struct.unpack_from('<I', mbr, 458)[0] == min(end // 512 - 1, 0xFFFFFFFF))
    return dict(ok=reciprocal and protective, primary_valid=bool(primary),
                backup_valid=bool(backup), reciprocity=reciprocal, protective_mbr=protective)


def mbr_read(path, end):
    sector = read_at(path, 0, 512)
    if sector[510:] != b'\x55\xaa':
        return None
    parts = []
    for i in range(4):
        entry = sector[446 + i * 16:462 + i * 16]
        if entry == b'\0' * 16:
            continue
        start, count = struct.unpack_from('<II', entry, 8)
        if entry[0] not in (0, 0x80) or not entry[4] or not start or not count:
            return None
        parts.append(dict(off=start * 512, size=count * 512, active=entry[0], type=entry[4]))
    if not parts or sum(p['active'] == 0x80 for p in parts) > 1 or not partitions_valid(parts, end):
        return None
    return parts


def descriptor_path(path):
    base = path[:-6] if path.lower().endswith('.babyk') else path
    return base[:-10] + '.vmdk' if base.lower().endswith('-flat.vmdk') else None


def topology(path):
    clean = path[:-6] if path.lower().endswith('.babyk') else path
    low = clean.lower()
    if not low.endswith('-flat.vmdk') or re.search(r'-\d{6}-flat\.vmdk$', low):
        return dict(ok=False, state='BLOCKED_UNSUPPORTED_VMDK_LAYOUT', reason='not a proven base flat extent')
    prefix = os.path.basename(clean)[:-10]
    related = [n for n in os.listdir(os.path.dirname(path)) if n.lower().startswith(prefix.lower())]
    neighbors = os.listdir(os.path.dirname(path))
    if any(re.search(r'-(?:\d{6}|delta|sesparse)', n.lower()) for n in related) or any(
            n.lower().endswith('.vmsd') and os.path.getsize(os.path.join(os.path.dirname(path), n)) > 0 for n in neighbors):
        return dict(ok=False, state='BLOCKED_UNSUPPORTED_VMDK_LAYOUT', reason='snapshot/chain evidence present')
    magic = read_at(path, 0, min(4, os.path.getsize(path)))
    if magic in (b'KDMV', b'COWD', b'\xbe\xba\xfe\xca'):
        return dict(ok=False, state='BLOCKED_UNSUPPORTED_VMDK_LAYOUT', reason='sparse header despite flat name')
    return dict(ok=True, backing_type='FLAT', extent_type='VMFS', snapshot=False,
                parent='NONE', descriptor=descriptor_path(path), related_files=related)


def descriptor_check(path, backing, end, native=None, expected_name=None):
    try:
        if os.path.getsize(path) > 1024 * 1024:
            return dict(ok=False, semantic=dict(available=False, ok=False), reason='oversized descriptor unsupported')
        text = read_at(path, 0, os.path.getsize(path)).decode('utf-8')
        extents = re.findall(r'^RW\s+(\d+)\s+(\w+)\s+"([^"\r\n]+)"\s*$', text, re.M)
        field_list = re.findall(r'^\s*(\w+)\s*=\s*"?([^"\s]+)"?\s*$', text, re.M)
        fields = dict(field_list)
        extent_lines = re.findall(r'^\s*(?:RW|RDONLY|NOACCESS)\b.*$', text, re.M)
        ok = (len(fields) == len(field_list) and len(extent_lines) == len(extents) == 1 and
              extents[0] == (str(end // 512), 'VMFS', expected_name or os.path.basename(backing))
              and fields.get('createType') == 'vmfs' and fields.get('parentCID') == 'ffffffff'
              and fields.get('version') == '1' and bool(re.fullmatch('[0-9a-fA-F]{8}', fields.get('CID', '')))
              and 'parentFileNameHint' not in text and os.path.exists(backing) and end % 512 == 0)
        semantic = command([native, '-e', path]) if native else dict(available=False, returncode=None,
                                                                    output='VMware native oracle unavailable')
        return dict(ok=ok, semantic=dict(available=semantic['available'],
                                        ok=semantic['returncode'] == 0, details=semantic))
    except (OSError, ValueError, RecoveryError):
        return dict(ok=False, semantic=dict(available=False, ok=False))


def scan_ntfs(disk, workspace, tail_mb=2048, progress=print):
    """Original overlapping head/tail strategy, checkpointed per window.

    No-hit observations explicitly apply only to these regions. A changed
    fingerprint invalidates the entire checkpoint, including rejected hits.
    """
    key = sha(disk.path.encode('utf-8'))
    checkpoint = os.path.join(workspace.path, 'checkpoints', key + '.json')
    end, tail = disk.data_end, tail_mb * 1024 * 1024
    ranges = [(0, min(2 << 30, end))]
    tail_start = max(0, end - tail)
    if tail_start <= ranges[0][1]:
        ranges[0] = (0, end)
    elif tail:
        ranges.append((tail_start, end))
    state = dict(fingerprint=disk.fingerprint, regions=ranges, region=0, position=0,
                 hits=[], rejected=[], complete=False, bytes_processed=0)
    if os.path.exists(checkpoint):
        cached = load_json(checkpoint)
        if cached['fingerprint'] == disk.fingerprint and cached['regions'] == [list(r) for r in ranges]:
            state = cached
    started, last_progress = time.monotonic(), time.monotonic()
    total = sum(b - a for a, b in ranges)
    prior_bytes = state['bytes_processed']
    while state['region'] < len(ranges):
        start, stop = ranges[state['region']]
        pos = max(start, state['position'])
        if pos >= stop:
            state['region'] += 1
            state['position'] = ranges[state['region']][0] if state['region'] < len(ranges) else stop
            continue
        length = min(8 * 1024 * 1024, stop - pos)
        buffer = read_at(disk.path, pos, length)
        idx = 0
        while True:
            found = buffer.find(b'NTFS    ', idx)
            if found < 0:
                break
            off = pos + found - 3
            if off >= 0 and off % 512 == 0 and off + 512 <= end:
                bpb = parse_ntfs(read_at(disk.path, off, 512))
                entry = dict(offset=off, bpb=bpb)
                destination = state['hits'] if bpb else state['rejected']
                if not any(e['offset'] == off for e in destination):
                    destination.append(entry)
            idx = found + 1
        step = length if pos + length == stop else length - 16
        state['position'] = pos + step
        state['bytes_processed'] += step
        atomic_json(checkpoint, state)
        elapsed = time.monotonic() - started
        if time.monotonic() - last_progress >= 5:
            speed = (state['bytes_processed'] - prior_bytes) / max(elapsed, 0.001)
            progress('%s region %d/%d bytes=%d MiB/s=%.2f elapsed=%.1fs ETA=%.1fs checkpoint=%s' % (
                disk.path, state['region'] + 1, len(ranges), state['bytes_processed'],
                speed / 1048576, elapsed, (total - state['bytes_processed']) / max(speed, 1), checkpoint))
            last_progress = time.monotonic()
    if fingerprint(disk.path, 'full_sha256' in disk.fingerprint) != disk.fingerprint:
        raise RecoveryError('SOURCE_CHANGED', 'scan source changed; checkpoint cannot be reused')
    state['complete'] = True
    atomic_json(checkpoint, state)
    if time.monotonic() - started >= 5:
        progress('DONE/CHECKED %s' % disk.path)
    return state


def diagnose(disk, scanned):
    diagnosis = Diagnosis()
    diagnosis.evidence.append(Evidence('PRIMARY_SURVIVOR', 'NTFS search scope only; no global absence claim',
                                       scanned['regions']))
    backup = gpt_read(disk.path, disk.data_end)
    primary = gpt_read(disk.path, disk.data_end, True)
    mbr = mbr_read(disk.path, disk.data_end)
    if backup:
        diagnosis.table = 'GPT'
        diagnosis.partitions = backup['partitions']
        if primary and (primary['array'] != backup['array'] or
                        primary['header']['disk_guid'] != backup['header']['disk_guid']):
            diagnosis.blockers.append('BLOCKED_CONFLICTING_EVIDENCE')
    elif primary:
        diagnosis.table = 'GPT_PRIMARY_ONLY'
        diagnosis.partitions = primary['partitions']
        diagnosis.blockers.append('BLOCKED_INSUFFICIENT_EVIDENCE')
    elif mbr and not any(p['type'] in (0xEE, 0x05, 0x0F, 0x85) for p in mbr):
        diagnosis.table = 'MBR'
        diagnosis.partitions = mbr
    else:
        diagnosis.table = 'UNKNOWN'
        if read_at(disk.path, 512, min(8, max(0, disk.data_end - 512))) == b'EFI PART' or any(
                p['type'] == 0xEE for p in (mbr or [])) or read_at(disk.path, disk.data_end - 512, 8) == b'EFI PART':
            diagnosis.blockers.append('BLOCKED_INSUFFICIENT_EVIDENCE')
        if any(p['type'] in (0x05, 0x0F, 0x85) for p in (mbr or [])):
            diagnosis.blockers.append('BLOCKED_UNSUPPORTED_LAYOUT')
    raw_candidates = []
    for hit in scanned['hits']:
        off, bpb = hit['offset'], hit['bpb']
        implied = off - bpb['total'] * bpb['bps']
        for start, source in ((off, 'PRIMARY_SURVIVOR'), (implied, 'BACKUP_SURVIVOR')):
            if start < 512 or start % 512:
                continue
            candidate = Candidate(start, bpb['vol_bytes'], off, bpb,
                                  Evidence(source, 'surviving NTFS sector at %d' % off,
                                           dict(offset=off, length=512)), {})
            candidate.checks = ntfs_checks(disk.path, candidate)
            if not candidate.checks['ok']:
                candidate.state, candidate.reason = 'REJECTED', 'BPB/extent/backup/MFT validation failed'
                diagnosis.rejected.append(candidate)
                continue
            matching = [p for p in diagnosis.partitions if p['off'] == start and p['size'] == candidate.size]
            if diagnosis.partitions and not matching:
                candidate.state, candidate.reason = 'REJECTED', 'independent partition table contradicts extent'
                diagnosis.rejected.append(candidate)
                continue
            raw_candidates.append(candidate)
    grouped = {}
    for candidate in raw_candidates:
        grouped.setdefault(candidate.start, []).append(candidate)
    for start, candidates in sorted(grouped.items()):
        geometries = {}
        for candidate in candidates:
            identity = (candidate.size, candidate.bpb['serial'], candidate.bpb['mft'],
                        candidate.bpb['mirr'], candidate.bpb['record_size'])
            previous = geometries.get(identity)
            if previous is None or candidate.sector_offset == candidate.start:
                geometries[identity] = candidate
        surviving_primary = parse_ntfs(read_at(disk.path, start, 512))
        chosen = [c for c in geometries.values() if surviving_primary == c.bpb]
        if len(chosen) == 1:
            for candidate in geometries.values():
                if candidate is not chosen[0]:
                    candidate.state, candidate.reason = 'REJECTED', 'surviving primary contradicts historical extent'
                    diagnosis.rejected.append(candidate)
        elif len(geometries) == 1:
            chosen = list(geometries.values())
        else:
            # Oversized stale extents crossing another independently validated
            # volume are rejected. Merely being larger is NOT sufficient.
            independent_starts = [s for s, group in grouped.items() if s != start and
                                  len({c.size for c in group}) == 1]
            chosen = []
            for candidate in geometries.values():
                if any(start < s < start + candidate.size for s in independent_starts):
                    candidate.state, candidate.reason = 'REJECTED', 'oversized historical extent overlaps independent filesystem'
                    diagnosis.rejected.append(candidate)
                else:
                    chosen.append(candidate)
            if len(chosen) != 1:
                diagnosis.blockers.append('BLOCKED_CONFLICTING_EVIDENCE')
                for candidate in chosen:
                    candidate.state, candidate.reason = 'HYPOTHESIS', 'non-unique reconstruction'
                diagnosis.candidates.extend(chosen)
                continue
        for candidate in chosen:
            candidate.state = 'VERIFIED'
            diagnosis.candidates.append(candidate)
    if not partitions_valid([dict(off=c.start, size=c.size) for c in diagnosis.candidates], disk.data_end):
        diagnosis.blockers.append('BLOCKED_CONFLICTING_EVIDENCE')
    for hit in scanned['rejected']:
        diagnosis.evidence.append(Evidence('UNKNOWN', 'invalid NTFS signature candidate',
                                           dict(offset=hit['offset'], length=512), 'REJECTED'))
    diagnosis.blockers = sorted(set(diagnosis.blockers))
    return diagnosis


def candidate_context(candidate):
    return candidate.to_dict()


def from_context(value):
    return Candidate(value['start'], value['size'], value['sector_offset'], value['bpb'],
                     Evidence(**value['evidence']), value['checks'])


def plan_repair(disk, diagnosis, environment, adapter=None):
    plan = RepairPlan(disk)
    plan.blockers.extend(diagnosis.blockers)
    plan.gate_evaluation = dict(evidence_unique=not diagnosis.blockers,
                               environment_capable=environment.get('write_capable', False),
                               authorization='REQUIRED', backup='CREATED_AND_VERIFIED_AT_EXECUTION',
                               journal='PERSISTED_BEFORE_MUTATION', source_lock='RECHECK_AT_EXECUTION')
    layout = topology(disk.path)
    if not layout['ok']:
        plan.blockers.append(layout['state'])
    if not diagnosis.candidates:
        plan.blockers.append('BLOCKED_INSUFFICIENT_EVIDENCE')
    contexts = [candidate_context(c) for c in diagnosis.candidates]
    for candidate in diagnosis.candidates:
        sector = read_at(disk.path, candidate.sector_offset, 512)
        old = read_at(disk.path, candidate.start, 512)
        if old != sector:
            plan.add('PATCH', candidate.start, old, sector, candidate.evidence, 'NTFS',
                     'restore primary from independently verified backup', candidate_context(candidate))
    backup = gpt_read(disk.path, disk.data_end)
    if backup and not verify_gpt(disk.path, disk.data_end)['ok']:
        header = backup['header'].copy()
        header['disk_guid'] = bytes.fromhex(header['disk_guid'])
        array = bytes.fromhex(backup['array'])
        mbr, primary, array = legacy.build_primary_gpt(header, array, disk.data_end // 512)
        blob = mbr + primary + array
        ev = Evidence('BACKUP_SURVIVOR', 'backup GPT header/array CRC, bounds and partitions verified',
                      dict(offset=disk.data_end - 512, length=512))
        plan.add('PATCH', 0, read_at(disk.path, 0, len(blob)), blob, ev, 'GPT',
                 'reconstruct primary GPT and protective MBR from reciprocal backup',
                 dict(data_end=disk.data_end, volumes=contexts))
    elif diagnosis.table == 'UNKNOWN' and diagnosis.candidates:
        parts = [dict(off=c.start, size=c.size) for c in diagnosis.candidates]
        if len(parts) > 4 or any(p['off'] // 512 + p['size'] // 512 > 0xFFFFFFFF for p in parts):
            plan.blockers.append('BLOCKED_UNSUPPORTED_LAYOUT')
        elif partitions_valid(parts, disk.data_end):
            old = read_at(disk.path, 0, 512)
            blob = bytearray(legacy.build_mbr(parts, None, disk.data_end // 512, old[440:444]))
            blob[440:444] = old[440:444]  # never invent a disk signature
            ev = Evidence('STRUCTURAL_REDUNDANCY', 'unique NTFS backup geometry and valid MFT records', parts)
            plan.add('PATCH', 0, old, bytes(blob), ev, 'MBR', 'restore evidenced geometry; active state UNKNOWN',
                     dict(partitions=parts, volumes=contexts, active_state='UNKNOWN'))
    # The tail is an observation until renamed Babuk identity AND independent
    # sector-oriented geometry are established. Arbitrary unaligned raw files
    # are not truncated just because the size has a remainder.
    tail = disk.size - disk.data_end
    if tail:
        if not disk.path.lower().endswith('.babyk'):
            plan.blockers.append('BLOCKED_INSUFFICIENT_EVIDENCE')
        else:
            ev = Evidence('STRUCTURAL_REDUNDANCY', 'Babuk-renamed flat extent with validated filesystem geometry; sector remainder %d' % tail,
                          dict(offset=disk.data_end, length=tail))
            plan.add('TRUNCATE', disk.data_end, read_at(disk.path, disk.data_end, tail), b'', ev,
                     'ALIGNMENT', 'remove complete non-sector-aligned tail; retain every byte in backup',
                     dict(size=disk.data_end, volumes=contexts))
    clean = disk.path[:-6] if disk.path.lower().endswith('.babyk') else disk.path
    if clean != disk.path:
        ev = Evidence('PRIMARY_SURVIVOR', 'Babuk suffix on independently validated base-flat extent', disk.path)
        if os.path.lexists(clean):
            plan.blockers.append('BLOCKED_CONFLICTING_EVIDENCE')
        plan.add('RENAME', 0, b'', b'', ev, 'IDENTITY', 'restore backing filename without replacing a destination',
                 dict(destination=clean), destination=clean)
    desc = descriptor_path(clean)
    if layout['ok'] and desc:
        if os.path.exists(desc):
            check = descriptor_check(desc, disk.path, disk.data_end, environment.get('vmkfstools'))
            # A surviving descriptor usually names the clean backing even while
            # it is renamed. Validate its topology after the rename transaction.
            if clean != disk.path:
                check = descriptor_check(desc, disk.path, disk.data_end, expected_name=os.path.basename(clean))
            if not check['ok']:
                plan.blockers.append('BLOCKED_UNSUPPORTED_VMDK_LAYOUT')
        else:
            # Controller choice is operator evidence; the old hardcoded default
            # is not a verified VM relationship.
            if adapter not in ('lsilogic', 'buslogic', 'ide', 'pvscsi'):
                plan.blockers.append('BLOCKED_INSUFFICIENT_EVIDENCE')
            else:
                sectors = disk.data_end // 512
                text = ('# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nCID=fffffffe\n'
                        'parentCID=ffffffff\ncreateType="vmfs"\n\nRW %d VMFS "%s"\n\n'
                        'ddb.adapterType = "%s"\n' % (sectors, os.path.basename(clean), adapter))
                ev = Evidence('OPERATOR_SUPPLIED', 'controller=%s; base-flat topology and exact extent size verified' % adapter, layout)
                plan.add('CREATE', 0, b'', text.encode('utf-8'), ev, 'DESCRIPTOR',
                         'create descriptor for proven flat base only; retain encrypted descriptor',
                         dict(backing=clean, size=disk.data_end), path=desc)
    if plan.blockers:
        plan.blockers = sorted(set(plan.blockers))
        plan.verdict = plan.blockers[0]
    elif plan.actions:
        plan.verdict = 'WRITE_READY_VERIFIED' if environment.get('write_capable') else 'DAMAGED_RECOVERABLE'
    else:
        plan.verdict = 'HEALTHY_VERIFIED'
    return plan


def verify_action(action, path, environment):
    oracle, context = action['structural_oracle'], action['context']
    semantic = dict(available=False, ok=None, reason='not applicable to this operation')
    if oracle == 'NTFS':
        candidate = from_context(context)
        result = ntfs_checks(path, candidate, require_primary=True)
        semantic = result.pop('semantic')
    elif oracle == 'GPT':
        result = verify_gpt(path, context['data_end'])
    elif oracle == 'MBR':
        parts = mbr_read(path, os.path.getsize(path) // 512 * 512)
        expected = context['partitions']
        result = dict(ok=bool(parts) and [(p['off'], p['size']) for p in parts] ==
                      [(p['off'], p['size']) for p in expected] and all(p['active'] == 0 for p in parts),
                      active_state='UNKNOWN', partitions=parts)
    elif oracle == 'ALIGNMENT':
        result = dict(ok=os.path.getsize(path) == context['size'] and context['size'] % 512 == 0)
    elif oracle == 'IDENTITY':
        result = dict(ok=os.path.exists(path) and path == context['destination'])
    elif oracle == 'DESCRIPTOR':
        result = descriptor_check(path, context['backing'], context['size'], environment.get('vmkfstools'))
        semantic = result.pop('semantic')
    else:
        raise RecoveryError('INSUFFICIENT_EVIDENCE', 'unknown oracle')
    if oracle in ('GPT', 'MBR', 'ALIGNMENT'):
        checks = [ntfs_checks(path, from_context(v)) for v in context.get('volumes', [])]
        semantic = dict(available=bool(checks), ok=bool(checks) and all(c['semantic'].get('ok') for c in checks), details=checks)
        result['filesystem_extents'] = all(c['ok'] for c in checks)
        result['ok'] = result['ok'] and result['filesystem_extents']
    return dict(structural=result, semantic=semantic)


def load_transaction(folder):
    files = sorted(n for n in os.listdir(folder) if re.fullmatch(r'\d{4}_.+\.json', n))
    if not files:
        raise RecoveryError('JOURNAL_FAILURE', 'no durable transaction record')
    prior = None
    record = None
    for index, name in enumerate(files):
        data = read_at(os.path.join(folder, name), 0, os.path.getsize(os.path.join(folder, name)))
        record = json.loads(data.decode('utf-8'))
        if record.get('sequence') != index or record.get('previous_record_sha256') != prior:
            raise RecoveryError('JOURNAL_FAILURE', 'journal chain invalid')
        prior = sha(data)
    record['_folder'] = folder
    record['_last_record_sha256'] = prior
    return record


class Transaction(object):
    def __init__(self, workspace, action, gate, expected_fingerprint, authorization=False, fault=None):
        self.workspace, self.action, self.gate = workspace, action.copy(), gate
        self.expected_fingerprint = expected_fingerprint
        self.authorization, self.fault = authorization, fault
        self.folder = os.path.join(workspace.path, 'transactions', uuid.uuid4().hex)
        self.record = dict(transaction_id=os.path.basename(self.folder), timestamp=timestamp(),
                           run_id=action.get('run_id'),
                           source_path=action['source_path'], source_fingerprint=expected_fingerprint,
                           source_size=0 if action['operation_type'] == 'CREATE' else expected_fingerprint['size'],
                           operation_type=action['operation_type'], backup_length=action.get('backup_length', action['length']),
                           offset=action['offset'], length=action['length'],
                           backup_path=os.path.join(self.folder, 'original.bin'),
                           sha256_before=action['sha256_before'], sha256_planned=action['sha256_planned'],
                           sha256_after=None, evidence_class=action['evidence_class'],
                           evidence_description=action['evidence_description'], reason=action['reason'],
                           verification_results={}, action=self.action, sequence=-1,
                           previous_record_sha256=None)
        self.last_hash = None

    def event(self, state, **values):
        next_record = self.record.copy()
        next_record.update(values)
        next_record.update(transaction_state=state, timestamp=timestamp(),
                           sequence=self.record['sequence'] + 1, previous_record_sha256=self.last_hash)
        raw = json_bytes(next_record)
        try:
            immutable(os.path.join(self.folder, '%04d_%s.json' % (next_record['sequence'], state)), raw)
            self.record = next_record
            self.last_hash = sha(raw)
            if state == 'PLANNED':
                immutable(os.path.join(self.folder, 'transaction.json'), raw)
        except OSError as error:
            raise RecoveryError('JOURNAL_FAILURE', str(error))
        if self.fault:
            self.fault(state, self)

    def run(self):
        action = self.action
        path, operation = action['source_path'], action['operation_type']
        old = b'' if operation == 'CREATE' else read_at(path, action['offset'], action['length'])
        action['old_hex'] = old.hex()
        planned = bytes.fromhex(action['planned_hex'])
        if sha(old) != action['sha256_before'] or sha(planned) != action['sha256_planned']:
            raise RecoveryError('SOURCE_CHANGED', 'plan hashes differ from current bytes')
        self.gate.check(action, self.expected_fingerprint, self.authorization)
        os.mkdir(self.folder)
        sync_dir(os.path.dirname(self.folder))
        phase, mutated = 'PREWRITE', False
        try:
            self.event('PLANNED')
            immutable(self.record['backup_path'], old)
            immutable(os.path.join(self.folder, 'planned.bin'), planned)
            self.event('BACKUP_CREATED')
            if file_hash(self.record['backup_path']) != sha(old) or file_hash(os.path.join(self.folder, 'planned.bin')) != sha(planned):
                raise RecoveryError('BACKUP_FAILURE', 'independent backup hash mismatch')
            self.event('BACKUP_HASH_VERIFIED')
            # Context samples exclude exact replacement bytes. This permits
            # interrupted-write rollback without accepting changed sampled
            # neighbors; it does not claim full-file integrity.
            structural_ranges = evidence_ranges(action)
            self.record['compatibility'] = compatibility(self.expected_fingerprint['path'],
                                                          action['offset'], 0 if operation == 'CREATE' else action['length'], structural_ranges)
            self.event('JOURNAL_PREPARED')
            self.gate.check(action, self.expected_fingerprint, self.authorization)
            self.event('WRITE_STARTED')
            self.gate.check(action, self.expected_fingerprint, self.authorization)
            if file_hash(self.record['backup_path']) != sha(old) or file_hash(os.path.join(self.folder, 'planned.bin')) != sha(planned):
                raise RecoveryError('BACKUP_FAILURE', 'artifact changed after journal preparation; write blocked')
            phase, mutated = 'WRITE', True
            if operation == 'PATCH':
                with open(path, 'r+b') as handle:
                    handle.seek(action['offset'])
                    if handle.write(planned) != len(planned):
                        raise RecoveryError('WRITE_FAILURE', 'short source write')
                    handle.flush()
                    os.fsync(handle.fileno())
            elif operation == 'TRUNCATE':
                with open(path, 'r+b') as handle:
                    handle.truncate(action['offset'])
                    handle.flush()
                    os.fsync(handle.fileno())
            elif operation == 'RENAME':
                # The per-source lock and a no-clobber link prevent silently
                # overwriting an independently created destination. VMFS may
                # lack hardlink support: fail safely rather than rename-clobber.
                os.link(path, action['destination'])
                sync_dir(os.path.dirname(path))
                os.unlink(path)
                sync_dir(os.path.dirname(path))
                path = action['destination']
            elif operation == 'CREATE':
                immutable(path, planned)
            else:
                raise RecoveryError('UNSUPPORTED_LAYOUT', 'unknown mutation')
            self.event('WRITE_COMPLETED', effective_path=path)
            phase = 'READBACK'
            readback = read_at(path, action['offset'], len(planned))
            if operation == 'TRUNCATE' and os.path.getsize(path) != action['offset']:
                raise RecoveryError('READBACK_FAILURE', 'truncation size differs')
            if operation == 'RENAME' and fingerprint_content(path) != fingerprint_content(self.expected_fingerprint):
                raise RecoveryError('READBACK_FAILURE', 'renamed content differs')
            if operation == 'RENAME' and 'full_sha256' in self.expected_fingerprint and file_hash(path) != self.expected_fingerprint['full_sha256']:
                raise RecoveryError('READBACK_FAILURE', 'renamed full hash differs')
            self.record['sha256_after'] = sha(readback)
            immutable(os.path.join(self.folder, 'readback.bin'), readback)
            if readback != planned:
                raise RecoveryError('READBACK_FAILURE', 'exact readback mismatch')
            self.event('READBACK_VERIFIED', sha256_after=sha(readback))
            phase = 'STRUCTURAL_VERIFY'
            verification = verify_action(action, path, self.gate.environment)
            self.record['verification_results'] = verification
            immutable(os.path.join(self.folder, 'verification.json'), json_bytes(verification))
            if not verification['structural']['ok']:
                raise RecoveryError('STRUCTURAL_VERIFY_FAILURE', 'structural oracle rejected mutation')
            self.event('STRUCTURAL_VERIFIED', verification_results=verification)
            phase = 'SEMANTIC_VERIFY'
            semantic = verification['semantic']
            if semantic['available'] and not semantic['ok']:
                raise RecoveryError('SEMANTIC_VERIFY_FAILURE', 'semantic oracle rejected mutation')
            if semantic['available']:
                self.event('SEMANTIC_VERIFIED')
            # Absence is never called semantic verification. Commit still
            # records exact bytes and structural success; run verdict is partial
            # if a descriptor's independent native oracle was unavailable.
            self.event('COMMITTED', post_fingerprint=fingerprint(path, 'full_sha256' in self.expected_fingerprint),
                       semantic_status='VERIFIED' if semantic['available'] else 'UNKNOWN')
            return self.record.copy()
        except Exception as error:
            classification = error.classification if isinstance(error, RecoveryError) else (
                'WRITE_FAILURE' if phase == 'WRITE' else 'BACKUP_FAILURE' if phase == 'PREWRITE' else phase + '_FAILURE')
            self.event('FAILED_PREWRITE' if not mutated else 'FAILED_' + phase,
                       failure_classification=classification, error=str(error))
            if mutated:
                self.event('ROLLBACK_REQUIRED')
            raise RecoveryError(classification, str(error))


def fingerprint_content(value):
    if isinstance(value, str):
        value = fingerprint(value)
    return dict(size=value['size'], device=value['device'], inode=value['inode'], samples=value['samples'])


def evidence_ranges(action):
    context = action['context']
    values = [context] if action['structural_oracle'] == 'NTFS' else context.get('volumes', [])
    ranges = []
    for candidate in values:
        bpb = candidate['bpb']
        ranges.extend(((candidate['sector_offset'], 512),
                       (candidate['start'] + bpb['mft'] * bpb['cluster'], 8 * bpb['record_size']),
                       (candidate['start'] + bpb['mirr'] * bpb['cluster'], bpb['record_size'])))
    if action['structural_oracle'] == 'GPT':
        ranges.append((context['data_end'] - 512, 512))
    return ranges


def compatibility(path, off, length, extra_ranges=()):
    stat_value = os.stat(path)
    size = stat_value.st_size
    ranges = []
    for start in sorted(set((0, max(0, size // 2 - 32768), max(0, size - 65536),
                            max(0, off - 65536), min(size, off + length)))):
        stop = min(size, start + 65536)
        for a, b in ((start, min(stop, off)), (max(start, off + length), stop)):
            if b > a:
                ranges.append(dict(offset=a, length=b - a, sha256=sha(read_at(path, a, b - a))))
    for start, count in extra_ranges:
        stop = min(size, start + count)
        for a, b in ((start, min(stop, off)), (max(start, off + length), stop)):
            if b > a:
                ranges.append(dict(offset=a, length=b - a, sha256=sha(read_at(path, a, b - a))))
    return dict(device=stat_value.st_dev, inode=stat_value.st_ino, original_size=size, samples=ranges)


def _rollback_transaction(workspace, transaction_id, gate, authorization=False):
    if not re.fullmatch('[0-9a-f]{32}', transaction_id):
        raise RecoveryError('ROLLBACK_FAILURE', 'invalid transaction ID')
    folder = os.path.join(workspace.path, 'transactions', transaction_id)
    record = load_transaction(folder)
    action = record['action']
    operation = action['operation_type']
    path = record.get('effective_path', action['source_path'])
    if operation == 'RENAME' and os.path.exists(action['destination']):
        path = action['destination']
    lock_path = record['source_fingerprint']['path'] if operation == 'CREATE' else path
    with source_lock(lock_path, workspace.path):
        if not authorization:
            raise RecoveryError('ROLLBACK_FAILURE', 'explicit rollback authorization required')
        gate.use_probe(lock_path, gate.environment)
        # Never trust a path from a serialized manifest to select arbitrary
        # files as recovery evidence; artifact names are fixed in this folder.
        backup_path = os.path.join(folder, 'original.bin')
        if record['backup_path'] != backup_path:
            raise RecoveryError('BACKUP_FAILURE', 'backup path escapes transaction')
        if 'compatibility' not in record:
            if record['transaction_state'] not in ('PLANNED', 'BACKUP_CREATED', 'BACKUP_HASH_VERIFIED', 'FAILED_PREWRITE'):
                raise RecoveryError('ROLLBACK_FAILURE', 'missing prewrite compatibility evidence')
            expected = record['source_fingerprint']
            if fingerprint(lock_path, 'full_sha256' in expected) != expected:
                raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'prewrite transaction source differs')
            current = b'' if operation == 'CREATE' else read_at(path, action['offset'], action['length'])
            if sha(current) != record['sha256_before']:
                raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'prewrite bytes differ')
            transaction = Transaction(workspace, action, gate, expected, True)
            transaction.folder = folder
            transaction.record = {k: v for k, v in record.items() if not k.startswith('_')}
            transaction.last_hash = record['_last_record_sha256']
            transaction.event('ROLLED_BACK', no_mutation_required=True, rollback_readback_sha256=sha(current))
            transaction.event('ROLLED_BACK_VERIFIED')
            return transaction.record
        old = read_at(backup_path, 0, os.path.getsize(backup_path))
        planned = read_at(os.path.join(folder, 'planned.bin'), 0, os.path.getsize(os.path.join(folder, 'planned.bin')))
        if (record['offset'], record['length'], record['operation_type'], record['source_path']) != (
                action['offset'], action['length'], operation, action['source_path']):
            raise RecoveryError('JOURNAL_FAILURE', 'action and journal coordinates conflict')
        if sha(old) != record['sha256_before'] or len(old) != record.get('backup_length', action['length']) or sha(planned) != record['sha256_planned']:
            raise RecoveryError('BACKUP_FAILURE', 'rollback backup/planned hash or length differs')
        comp = record['compatibility']
        source = lock_path
        current_stat = os.stat(source)
        if (current_stat.st_dev, current_stat.st_ino) != (comp['device'], comp['inode']):
            raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'source identity differs')
        expected_sizes = {comp['original_size']}
        if operation == 'TRUNCATE':
            expected_sizes.add(action['offset'])
        if current_stat.st_size not in expected_sizes:
            raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'source size differs')
        for sample in comp['samples']:
            if sha(read_at(source, sample['offset'], sample['length'])) != sample['sha256']:
                raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'source context sample differs')
        if operation == 'CREATE':
            current = read_at(path, 0, os.path.getsize(path)) if os.path.exists(path) else b''
        elif operation == 'TRUNCATE':
            current = b'' if os.path.getsize(path) == action['offset'] else read_at(path, action['offset'], len(old))
        else:
            current = read_at(path, action['offset'], len(planned))
        if current not in (old, planned):
            raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'current bytes match neither known state')
        transaction = Transaction(workspace, action, gate, record['source_fingerprint'], True)
        transaction.folder, transaction.record = folder, {k: v for k, v in record.items() if not k.startswith('_')}
        transaction.last_hash = record['_last_record_sha256']
        # Every rollback is itself journaled before touching the source.
        transaction.event('ROLLBACK_REQUIRED', rollback_current_sha256=sha(current))
        if operation == 'RENAME':
            original = action['source_path']
            if original != path:
                if os.path.lexists(original):
                    if not os.path.samefile(original, path):
                        raise RecoveryError('ROLLBACK_SOURCE_STATE_CHANGED', 'original rename path occupied')
                else:
                    os.link(path, original)
                    sync_dir(os.path.dirname(path))
                os.unlink(path)
                sync_dir(os.path.dirname(path))
            path = original
            if fingerprint_content(path) != fingerprint_content(record['source_fingerprint']):
                raise RecoveryError('ROLLBACK_FAILURE', 'rename rollback readback differs')
            if 'full_sha256' in record['source_fingerprint'] and file_hash(path) != record['source_fingerprint']['full_sha256']:
                raise RecoveryError('ROLLBACK_FAILURE', 'rename rollback full hash differs')
        elif operation == 'CREATE':
            if os.path.exists(path):
                os.unlink(path)
                sync_dir(os.path.dirname(path))
            if os.path.lexists(path):
                raise RecoveryError('ROLLBACK_FAILURE', 'descriptor removal not verified')
        elif current != old:
            with open(path, 'r+b') as handle:
                handle.seek(action['offset'])
                if handle.write(old) != len(old):
                    raise RecoveryError('ROLLBACK_FAILURE', 'short restore write')
                handle.flush()
                os.fsync(handle.fileno())
        if operation in ('PATCH', 'TRUNCATE') and sha(read_at(path, action['offset'], len(old))) != record['sha256_before']:
            raise RecoveryError('ROLLBACK_FAILURE', 'restored readback mismatch')
        transaction.event('ROLLED_BACK', rollback_readback_sha256=sha(old))
        transaction.event('ROLLED_BACK_VERIFIED')
        return transaction.record


def rollback(workspace, transaction_id, gate, authorization=False):
    try:
        return _rollback_transaction(workspace, transaction_id, gate, authorization)
    except Exception as error:
        # A failed rollback attempt is forensic evidence too. Preserve the
        # original lifecycle state and append its failure without rewriting it.
        if re.fullmatch('[0-9a-f]{32}', transaction_id):
            folder = os.path.join(workspace.path, 'transactions', transaction_id)
            try:
                record = load_transaction(folder)
                transaction = Transaction(workspace, record['action'], gate, record['source_fingerprint'])
                transaction.folder = folder
                transaction.record = {k: v for k, v in record.items() if not k.startswith('_')}
                transaction.last_hash = record['_last_record_sha256']
                transaction.event(record['transaction_state'], rollback_failure_classification=(
                    error.classification if isinstance(error, RecoveryError) else 'ROLLBACK_FAILURE'),
                    rollback_error=str(error))
            except Exception:
                pass  # original failure remains primary; no source mutation
        raise


def execute_plan(plan, workspace, gate, authorization=False, fault=None):
    if plan.blockers:
        raise RecoveryError('INSUFFICIENT_EVIDENCE', ', '.join(plan.blockers))
    if workspace.incomplete(plan.disk.path):
        raise RecoveryError('JOURNAL_FAILURE', 'unfinished transaction must be inspected/rolled back first')
    records, path = [], plan.disk.path
    expected = plan.disk.fingerprint
    with source_lock(path, workspace.path):
        if fingerprint(path, 'full_sha256' in expected) != expected:
            raise RecoveryError('SOURCE_CHANGED', 'plan source differs')
        for original_action in plan.actions:
            action = original_action.copy()
            if action['operation_type'] != 'CREATE':
                action['source_path'] = path
            # Never retry the same failed action with identical source/plan.
            for name in os.listdir(os.path.join(workspace.path, 'transactions')):
                folder = os.path.join(workspace.path, 'transactions', name)
                if not os.path.isdir(folder):
                    continue
                prior = load_transaction(folder)
                if (prior.get('failure_classification') and prior['source_fingerprint'] == expected and
                        prior['operation_type'] == action['operation_type'] and prior['offset'] == action['offset'] and
                        prior['sha256_planned'] == action['sha256_planned']):
                    raise RecoveryError('INSUFFICIENT_EVIDENCE', 'rejected action unchanged; new evidence/variable required')
                if (prior.get('failure_classification') and prior['source_path'] == action['source_path'] and
                        prior['operation_type'] == action['operation_type'] and prior['offset'] == action['offset']):
                    action['retry_changed_variable'] = dict(previous_transaction_id=prior['transaction_id'],
                                                           source_fingerprint_changed=prior['source_fingerprint'] != expected,
                                                           planned_hash_changed=prior['sha256_planned'] != action['sha256_planned'])
            transaction = Transaction(workspace, action, gate, expected, authorization, fault)
            record = transaction.run()
            records.append(record)
            if action['operation_type'] == 'RENAME':
                path = action['destination']
            expected = fingerprint(path, 'full_sha256' in expected)
    return records, path
