"""Synthetic fixtures only. No production disk paths or mounts."""
import ast
import copy
import io
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import recovery_core as core
import babuk_recovery as cli


class SimulatedCrash(BaseException):
    pass


def record(seed=0, bps=512):
    value = bytearray(1024)
    value[:4] = b'FILE'
    struct.pack_into('<HH', value, 4, 48, 3)
    struct.pack_into('<HHII', value, 20, 56, 1, 92, 1024)
    value[48:54] = b'\xaa\xbb\x00\x00\x00\x00'
    struct.pack_into('<II', value, 56, 0x10, 32)
    struct.pack_into('<IH', value, 72, 8, 24)
    value[80:88] = bytes([seed]) * 8
    struct.pack_into('<I', value, 88, 0xFFFFFFFF)
    value[510:512] = value[1022:1024] = b'\xaa\xbb'
    return bytes(value)


def boot(start, size, mft=4, mirr=20):
    sector = bytearray(512)
    sector[0:3] = b'\xeb\x52\x90'
    sector[3:11] = b'NTFS    '
    struct.pack_into('<H', sector, 11, 512)
    sector[13] = 8
    struct.pack_into('<I', sector, 28, start // 512)
    struct.pack_into('<QQQ', sector, 40, size // 512 - 1, mft, mirr)
    sector[64] = 246  # -10, 1024-byte records
    struct.pack_into('<Q', sector, 72, 12345)
    sector[510:512] = b'\x55\xaa'
    return bytes(sector)


def put(path, offset, data):
    with open(path, 'r+b') as handle:
        handle.seek(offset)
        handle.write(data)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name
        self.work = core.Workspace(os.path.join(self.root, 'work'))
        self.path = os.path.join(self.root, 'vm-flat.vmdk')
        with open(self.path, 'wb') as handle:
            handle.truncate(8 * 1024 * 1024)
        self.start, self.size = 1024 * 1024, 4 * 1024 * 1024
        self.sector = boot(self.start, self.size)
        self.install_volume()
        self.environment = dict(write_capable=True, vmkfstools=None)
        self.gate = core.WriteGate(self.environment, lambda path, env: True)

    def tearDown(self):
        self.temp.cleanup()

    def install_volume(self, primary=True):
        if primary:
            put(self.path, self.start, self.sector)
        put(self.path, self.start + self.size - 512, self.sector)
        for i in range(8):
            put(self.path, self.start + 4 * 4096 + i * 1024, record(i))
        put(self.path, self.start + 20 * 4096, record(0))

    def candidate(self):
        bpb = core.parse_ntfs(self.sector)
        return core.Candidate(self.start, self.size, self.start + self.size - 512, bpb,
                              core.Evidence('BACKUP_SURVIVOR', 'verified fixture backup', 'fixture'), {})

    def diagnosis(self):
        disk = core.DiskState(self.path)
        scan = core.scan_ntfs(disk, self.work, 1, lambda message: None)
        return disk, core.diagnose(disk, scan)

    def patch_plan(self, oracle='NTFS', planned=None):
        put(self.path, self.start, b'\0' * 512)
        disk = core.DiskState(self.path)
        plan = core.RepairPlan(disk)
        plan.add('PATCH', self.start, b'\0' * 512, self.sector if planned is None else planned,
                 self.candidate().evidence, oracle, 'restore test backup', core.candidate_context(self.candidate()))
        return plan

    def transaction(self, fault=None, plan=None):
        plan = plan or self.patch_plan()
        records, path = core.execute_plan(plan, self.work, self.gate, True, fault)
        return records[0]

    def journal(self):
        names = os.listdir(os.path.join(self.work.path, 'transactions'))
        return core.load_transaction(os.path.join(self.work.path, 'transactions', names[-1]))

    def install_mbr(self):
        sector = bytearray(core.legacy.build_mbr([dict(off=self.start, size=self.size)], None,
                                                os.path.getsize(self.path) // 512))
        put(self.path, 0, sector)

    def install_descriptor(self):
        descriptor = core.descriptor_path(self.path)
        with open(descriptor, 'w') as handle:
            handle.write('version=1\nCID=abcdef12\nparentCID=ffffffff\ncreateType="vmfs"\n'
                         'RW %d VMFS "vm-flat.vmdk"\n' % (os.path.getsize(self.path) // 512))
        return descriptor

    def test_520_mib_boundary(self):
        self.assertEqual(core.DAMAGE, 520 * 1024 * 1024)
        self.assertNotEqual(core.DAMAGE, 512 * 1024 * 1024)
        # Compare the actual production loop, not just a repeated constant.
        tree = ast.parse((pathlib.Path(__file__).parent / 'reference_babuk_recover.py.txt').read_text(encoding='utf-8'))
        nodes = [n for n in tree.body if isinstance(n, (ast.Assign, ast.While)) and
                 (isinstance(n, ast.While) or any(isinstance(t, ast.Name) and t.id in ('_BLOCK', '_w', 'DAMAGE') for t in n.targets))]
        scope = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<reference boundary>', 'exec'), scope)
        self.assertEqual(core.DAMAGE, scope['DAMAGE'])

    def test_healthy_ntfs_boot_sector(self):
        result = core.ntfs_checks(self.path, self.candidate(), True)
        self.assertTrue(result['ok'])
        self.assertEqual(result['semantic']['details']['valid_records'], 8)

    def test_valid_mft_and_usa(self):
        self.assertIsNotNone(core.file_record(record(), 512))
        corrupt = bytearray(record())
        corrupt[510] = 0
        self.assertIsNone(core.file_record(corrupt, 512))

    def test_signature_only_mft_invalid(self):
        self.assertIsNone(core.file_record(b'FILE' + b'\0' * 1020, 512))

    def test_invalid_mft_blocks_all_source_writes(self):
        for i in range(8):
            put(self.path, self.start + 4 * 4096 + i * 1024, b'FILE' + b'\0' * 1020)
        before = core.file_hash(self.path)
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertTrue(plan.blockers)
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(before, core.file_hash(self.path))
        self.assertEqual([], os.listdir(os.path.join(self.work.path, 'transactions')))

    def test_missing_primary_valid_backup_discovered(self):
        put(self.path, self.start, b'\0' * 512)
        disk, diagnosis = self.diagnosis()
        self.assertEqual([self.start], [c.start for c in diagnosis.candidates])
        self.assertEqual('BACKUP_SURVIVOR', diagnosis.candidates[0].evidence.evidence_class)

    def test_invalid_backup_rejected(self):
        put(self.path, self.start + self.size - 512, b'\0' * 512)
        self.assertFalse(core.ntfs_checks(self.path, self.candidate())['ok'])

    def test_partition_offset_conflict_rejected(self):
        wrong = bytearray(self.sector)
        struct.pack_into('<I', wrong, 28, 99)
        put(self.path, self.start + self.size - 512, wrong)
        candidate = self.candidate()
        candidate.bpb = core.parse_ntfs(wrong)
        self.assertFalse(core.ntfs_checks(self.path, candidate)['ok'])

    def test_mftmirr_conflict_rejected(self):
        put(self.path, self.start + 20 * 4096, record(7))
        self.assertFalse(core.ntfs_checks(self.path, self.candidate())['ok'])

    def test_stale_oversized_backup_rejected_by_surviving_primary(self):
        stale_size = 6 * 1024 * 1024
        stale = boot(self.start, stale_size)
        put(self.path, self.start + stale_size - 512, stale)
        disk, diagnosis = self.diagnosis()
        self.assertEqual([self.size], [c.size for c in diagnosis.candidates])
        self.assertTrue(any(c.size == stale_size and c.state == 'REJECTED' for c in diagnosis.rejected))

    def test_two_plausible_backup_geometries_block(self):
        put(self.path, self.start, b'\0' * 512)
        stale_size = 6 * 1024 * 1024
        put(self.path, self.start + stale_size - 512, boot(self.start, stale_size))
        disk, diagnosis = self.diagnosis()
        self.assertIn('BLOCKED_CONFLICTING_EVIDENCE', diagnosis.blockers)
        before = core.file_hash(self.path)
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(before, core.file_hash(self.path))

    def test_partition_overlap_rejected(self):
        self.assertFalse(core.partitions_valid([dict(off=512, size=1024), dict(off=1024, size=512)], 4096))

    def test_mbr_reconstruction_no_largest_active(self):
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        action = next(a for a in plan.actions if a['structural_oracle'] == 'MBR')
        sector = bytes.fromhex(action['planned_hex'])
        self.assertEqual([0, 0, 0, 0], [sector[446 + i * 16] for i in range(4)])
        self.assertEqual('UNKNOWN', action['context']['active_state'])
        self.assertEqual(b'\0' * 4, sector[440:444])

    def test_mbr_invalid_overlap(self):
        sector = core.legacy.build_mbr([dict(off=512, size=1024), dict(off=1024, size=512)], None, 16384)
        put(self.path, 0, sector)
        self.assertIsNone(core.mbr_read(self.path, os.path.getsize(self.path)))

    def test_safe_flat_descriptor_plan(self):
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'pvscsi')
        action = next(a for a in plan.actions if a['operation_type'] == 'CREATE')
        self.assertIn(b'VMFS "vm-flat.vmdk"', bytes.fromhex(action['planned_hex']))
        self.assertIn(b'pvscsi', bytes.fromhex(action['planned_hex']))
        self.assertEqual(len(bytes.fromhex(action['planned_hex'])), action['length'])
        self.assertEqual(0, action['backup_length'])

    def test_descriptor_requires_controller_evidence(self):
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment)
        self.assertIn('BLOCKED_INSUFFICIENT_EVIDENCE', plan.blockers)

    def test_sparse_and_snapshot_layouts_blocked(self):
        for name in ('vm-sesparse.vmdk', 'vm-delta.vmdk', 'vm-000001-flat.vmdk'):
            path = os.path.join(self.root, name)
            with open(path, 'wb') as handle:
                handle.write(b'\0' * 512)
            self.assertEqual('BLOCKED_UNSUPPORTED_VMDK_LAYOUT', core.topology(path)['state'])
        self.assertFalse(core.topology(self.path)['ok'])

    def test_sparse_magic_with_flat_name_blocked(self):
        put(self.path, 0, b'KDMV')
        self.assertFalse(core.topology(self.path)['ok'])

    def test_existing_descriptor_is_independently_parsed(self):
        descriptor = self.install_descriptor()
        self.assertTrue(core.descriptor_check(descriptor, self.path, os.path.getsize(self.path))['ok'])
        put(descriptor, 0, b'garbage')
        self.assertFalse(core.descriptor_check(descriptor, self.path, os.path.getsize(self.path))['ok'])

    def test_native_nonzero_is_semantic_failure(self):
        descriptor = self.install_descriptor()
        with mock.patch.object(core, 'command', return_value=dict(available=True, returncode=1, output='broken chain')):
            result = core.descriptor_check(descriptor, self.path, os.path.getsize(self.path), 'vmkfstools')
        self.assertTrue(result['ok'])
        self.assertFalse(result['semantic']['ok'])

    def test_complete_transaction_journal_chain(self):
        record_value = self.transaction()
        self.assertEqual('COMMITTED', record_value['transaction_state'])
        journal = self.journal()
        self.assertEqual(core.sha(self.sector), journal['sha256_after'])
        self.assertTrue(os.path.isfile(os.path.join(journal['_folder'], 'original.bin')))
        states = [name for name in os.listdir(journal['_folder']) if name.endswith('.json')]
        self.assertTrue(any('JOURNAL_PREPARED' in state for state in states))
        self.assertTrue(any('SEMANTIC_VERIFIED' in state for state in states))

    def test_prewrite_journal_durable_before_mutation(self):
        def fault(state, transaction):
            if state == 'WRITE_STARTED':
                self.assertEqual('WRITE_STARTED', core.load_transaction(transaction.folder)['transaction_state'])
                self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))
                raise SimulatedCrash()
        with self.assertRaises(SimulatedCrash):
            self.transaction(fault)
        journal = self.journal()
        self.assertEqual('WRITE_STARTED', journal['transaction_state'])
        self.assertEqual(1, len(self.work.incomplete(self.path)))
        restored = core.rollback(self.work, journal['transaction_id'], self.gate, True)
        self.assertEqual('ROLLED_BACK_VERIFIED', restored['transaction_state'])

    def test_interruption_after_write_recovered_from_journal(self):
        def fault(state, transaction):
            if state == 'WRITE_COMPLETED':
                raise SimulatedCrash()
        with self.assertRaises(SimulatedCrash):
            self.transaction(fault)
        journal = self.journal()
        self.assertEqual(self.sector, core.read_at(self.path, self.start, 512))
        core.rollback(self.work, journal['transaction_id'], self.gate, True)
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_successful_rollback_and_repeated_rollback(self):
        transaction = self.transaction()
        for _ in range(2):
            result = core.rollback(self.work, transaction['transaction_id'], self.gate, True)
            self.assertEqual('ROLLED_BACK_VERIFIED', result['transaction_state'])
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_rollback_unexpected_current_bytes_blocked(self):
        transaction = self.transaction()
        put(self.path, self.start, b'X' * 512)
        with self.assertRaisesRegex(core.RecoveryError, 'ROLLBACK_SOURCE_STATE_CHANGED'):
            core.rollback(self.work, transaction['transaction_id'], self.gate, True)
        self.assertEqual(b'X' * 512, core.read_at(self.path, self.start, 512))

    def test_rollback_changed_context_blocked(self):
        transaction = self.transaction()
        put(self.path, 512, b'Y')
        with self.assertRaisesRegex(core.RecoveryError, 'ROLLBACK_SOURCE_STATE_CHANGED'):
            core.rollback(self.work, transaction['transaction_id'], self.gate, True)

    def test_corrupt_backup_blocks_rollback(self):
        transaction = self.transaction()
        put(transaction['backup_path'], 0, b'X')
        with self.assertRaisesRegex(core.RecoveryError, 'BACKUP_FAILURE'):
            core.rollback(self.work, transaction['transaction_id'], self.gate, True)

    def test_readback_mismatch_detected(self):
        def fault(state, transaction):
            if state == 'WRITE_COMPLETED':
                put(self.path, self.start, b'X')
        with self.assertRaisesRegex(core.RecoveryError, 'READBACK_FAILURE'):
            self.transaction(fault)
        self.assertEqual('ROLLBACK_REQUIRED', self.journal()['transaction_state'])
        self.assertEqual(core.sha(core.read_at(self.path, self.start, 512)), self.journal()['sha256_after'])

    def test_structural_failure_not_committed(self):
        with self.assertRaisesRegex(core.RecoveryError, 'STRUCTURAL_VERIFY_FAILURE'):
            self.transaction(plan=self.patch_plan(planned=b'\0' * 512))
        self.assertEqual('ROLLBACK_REQUIRED', self.journal()['transaction_state'])
        self.assertFalse(self.journal()['verification_results']['structural']['ok'])

    def test_semantic_failure_not_committed(self):
        verification = dict(structural=dict(ok=True), semantic=dict(available=True, ok=False))
        with mock.patch.object(core, 'verify_action', return_value=verification):
            with self.assertRaisesRegex(core.RecoveryError, 'SEMANTIC_VERIFY_FAILURE'):
                self.transaction()
        self.assertEqual('ROLLBACK_REQUIRED', self.journal()['transaction_state'])

    def test_busy_source_zero_writes(self):
        plan = self.patch_plan()
        before = core.file_hash(self.path)
        def busy(path, environment):
            raise core.RecoveryError('SOURCE_IN_USE', 'fixture VM lock')
        gate = core.WriteGate(self.environment, busy)
        with self.assertRaisesRegex(core.RecoveryError, 'SOURCE_IN_USE'):
            core.execute_plan(plan, self.work, gate, True)
        self.assertEqual(before, core.file_hash(self.path))
        self.assertEqual([], os.listdir(os.path.join(self.work.path, 'transactions')))

    def test_source_use_native_lock_requires_explicit_mode_zero(self):
        for output in ('', 'Lock mode 1', 'Lock mode 0\nLock mode 2'):
            with mock.patch.object(core, 'command', return_value=dict(available=True, returncode=0, output=output)):
                with self.assertRaises(core.RecoveryError):
                    core.source_use(self.path, dict(write_capable=True, vmkfstools='fixture'))
        with mock.patch.object(core, 'command', return_value=dict(available=True, returncode=0, output='Lock mode 0')):
            self.assertEqual(0, core.source_use(self.path, dict(write_capable=True, vmkfstools='fixture'))['returncode'])

    def test_missing_authorization_zero_writes(self):
        plan = self.patch_plan()
        before = core.file_hash(self.path)
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, False)
        self.assertEqual(before, core.file_hash(self.path))

    def test_inferred_evidence_zero_writes(self):
        plan = self.patch_plan()
        plan.actions[0]['evidence']['evidence_class'] = 'INFERRED'
        before = core.file_hash(self.path)
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(before, core.file_hash(self.path))

    def test_source_fingerprint_changed_blocks_write(self):
        plan = self.patch_plan()
        put(self.path, 0, b'X')
        before = core.file_hash(self.path)
        with self.assertRaisesRegex(core.RecoveryError, 'SOURCE_CHANGED'):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(before, core.file_hash(self.path))

    def test_backup_failure_zero_writes(self):
        plan = self.patch_plan()
        before = core.file_hash(self.path)
        actual = core.immutable
        def fail(path, data):
            if path.endswith('original.bin'):
                raise core.RecoveryError('BACKUP_FAILURE', 'fixture full datastore')
            return actual(path, data)
        with mock.patch.object(core, 'immutable', side_effect=fail):
            with self.assertRaises(core.RecoveryError):
                self.transaction(plan=plan)
        self.assertEqual(before, core.file_hash(self.path))
        self.assertEqual('FAILED_PREWRITE', self.journal()['transaction_state'])

    def test_journal_failure_zero_writes(self):
        plan = self.patch_plan()
        before = core.file_hash(self.path)
        actual = core.immutable
        def fail(path, data):
            if 'JOURNAL_PREPARED' in path:
                raise core.RecoveryError('JOURNAL_FAILURE', 'fixture journal fsync failure')
            return actual(path, data)
        with mock.patch.object(core, 'immutable', side_effect=fail):
            with self.assertRaises(core.RecoveryError):
                self.transaction(plan=plan)
        self.assertEqual(before, core.file_hash(self.path))

    def test_artifacts_not_overwritten(self):
        path = os.path.join(self.root, 'evidence.bin')
        core.immutable(path, b'first')
        with self.assertRaises(FileExistsError):
            core.immutable(path, b'second')
        self.assertEqual(b'first', core.read_at(path, 0, 5))

    def test_rejected_failed_action_not_retried(self):
        plan = self.patch_plan()
        actual = core.immutable
        def fail(path, data):
            if path.endswith('original.bin'):
                raise core.RecoveryError('BACKUP_FAILURE', 'fixture')
            return actual(path, data)
        with mock.patch.object(core, 'immutable', side_effect=fail):
            with self.assertRaises(core.RecoveryError):
                self.transaction(plan=plan)
        with self.assertRaisesRegex(core.RecoveryError, 'rejected action unchanged'):
            core.execute_plan(plan, self.work, self.gate, True)

    def test_checkpoint_reused_only_exact_fingerprint(self):
        disk = core.DiskState(self.path)
        first = core.scan_ntfs(disk, self.work, 1, lambda text: None)
        second = core.scan_ntfs(disk, self.work, 1, lambda text: None)
        self.assertEqual(first['hits'], second['hits'])
        put(self.path, self.start + self.size - 512, b'\0' * 512)
        changed = core.scan_ntfs(core.DiskState(self.path), self.work, 1, lambda text: None)
        self.assertNotEqual(first['fingerprint'], changed['fingerprint'])
        self.assertNotEqual(first['hits'], changed['hits'])

    def test_tail_one_multiple_and_nonstandard_lengths_rollback(self):
        for length in (32, 64, 96, 31):
            with self.subTest(length=length):
                path = self.path + '.babyk'
                os.rename(self.path, path)
                with open(path, 'ab') as handle:
                    handle.write(b'T' * length)
                disk = core.DiskState(path)
                self.assertEqual(length, disk.size - disk.data_end)
                plan = core.RepairPlan(disk)
                candidate = core.candidate_context(self.candidate())
                ev = core.Evidence('STRUCTURAL_REDUNDANCY', 'fixture verified renamed disk', path)
                plan.add('TRUNCATE', disk.data_end, b'T' * length, b'', ev, 'ALIGNMENT', 'fixture tail',
                         dict(size=disk.data_end, volumes=[candidate]))
                records, _ = core.execute_plan(plan, self.work, self.gate, True)
                self.assertEqual(8 * 1024 * 1024, os.path.getsize(path))
                core.rollback(self.work, records[0]['transaction_id'], self.gate, True)
                self.assertEqual(b'T' * length, core.read_at(path, disk.data_end, length))
                with open(path, 'r+b') as handle:
                    handle.truncate(disk.data_end)
                os.rename(path, self.path)

    def test_arbitrary_unaligned_nonbabuk_file_not_truncated(self):
        with open(self.path, 'ab') as handle:
            handle.write(b'X' * 32)
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertTrue(plan.blockers)
        self.assertFalse(any(a['operation_type'] == 'TRUNCATE' for a in plan.actions))

    def test_no_clobber_rename_and_rollback(self):
        original = self.path + '.babyk'
        os.rename(self.path, original)
        disk = core.DiskState(original)
        plan = core.RepairPlan(disk)
        ev = core.Evidence('PRIMARY_SURVIVOR', 'fixture renamed backing', original)
        plan.add('RENAME', 0, b'', b'', ev, 'IDENTITY', 'restore name',
                 dict(destination=self.path), destination=self.path)
        records, path = core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(self.path, path)
        self.assertFalse(os.path.exists(original))
        core.rollback(self.work, records[0]['transaction_id'], self.gate, True)
        self.assertTrue(os.path.exists(original))
        self.assertFalse(os.path.exists(self.path))

    def test_rename_collision_zero_writes(self):
        plan = core.RepairPlan(core.DiskState(self.path))
        dest = os.path.join(self.root, 'existing.vmdk')
        with open(dest, 'wb') as handle:
            handle.write(b'existing')
        plan.add('RENAME', 0, b'', b'', self.candidate().evidence, 'IDENTITY', 'fixture',
                 dict(destination=dest), destination=dest)
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(b'existing', core.read_at(dest, 0, 8))

    def test_repeated_execution_repaired_disk_has_no_mutation_plan(self):
        self.install_mbr()
        self.install_descriptor()
        self.transaction()
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertEqual([], plan.actions)
        self.assertEqual([], plan.blockers)

    def test_dry_run_zero_source_mutations_and_report(self):
        before = core.file_hash(self.path)
        with mock.patch.object(core, 'preflight', return_value=dict(write_capable=False, vmkfstools=None, esxi={})), mock.patch('sys.stdout', new=io.StringIO()):
            cli.main(['--dry-run', '--source', self.path, '--work-dir', self.work.path, '--adapter', 'lsilogic'])
        self.assertEqual(before, core.file_hash(self.path))
        self.assertEqual([], os.listdir(os.path.join(self.work.path, 'transactions')))
        report = core.load_json(os.path.join(self.work.path, 'state', 'latest_run.json'))
        action = report['source_disks'][0]['repair_plan']['actions'][0]
        for name in ('offset', 'length', 'sha256_before', 'sha256_planned', 'evidence',
                     'structural_oracle', 'semantic_oracle', 'rollback_artifact'):
            self.assertIn(name, action)

    def test_eof_is_not_consent(self):
        with mock.patch('sys.stdin', io.StringIO('')), mock.patch('sys.stdout', io.StringIO()):
            self.assertEqual('q', core.legacy.ask('repair?', ['y', 'n', 'q'], 'n'))

    def test_descriptor_creation_rollback_preserves_encrypted_evidence(self):
        self.install_mbr()
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        desc = core.descriptor_path(self.path)
        encrypted = desc + '.babyk'
        with open(encrypted, 'wb') as handle:
            handle.write(b'historical evidence')
        records, _ = core.execute_plan(plan, self.work, self.gate, True)
        self.assertTrue(os.path.exists(desc))
        core.rollback(self.work, records[0]['transaction_id'], self.gate, True)
        self.assertFalse(os.path.exists(desc))
        self.assertTrue(os.path.exists(encrypted))

    def test_journal_chain_tampering_detected(self):
        self.transaction()
        journal = self.journal()
        first = os.path.join(journal['_folder'], '0000_PLANNED.json')
        value = core.load_json(first)
        value['reason'] = 'tampered'
        with open(first, 'w') as handle:
            json.dump(value, handle)
        with self.assertRaisesRegex(core.RecoveryError, 'JOURNAL_FAILURE'):
            core.load_transaction(journal['_folder'])

    def install_gpt(self):
        end = os.path.getsize(self.path)
        sectors = end // 512
        array = bytearray(128 * 128)
        array[:16] = b'\x01' * 16
        array[16:32] = b'\x02' * 16
        struct.pack_into('<QQ', array, 32, self.start // 512, (self.start + self.size) // 512 - 1)
        header = dict(revision=0x10000, first_usable=34, last_usable=sectors - 34,
                      disk_guid=b'\x03' * 16, num=128, esz=128)
        mbr, primary, raw_array = core.legacy.build_primary_gpt(header, bytes(array), sectors)
        backup = bytearray(primary)
        struct.pack_into('<QQ', backup, 24, sectors - 1, 1)
        struct.pack_into('<Q', backup, 72, sectors - 33)
        struct.pack_into('<I', backup, 16, 0)
        struct.pack_into('<I', backup, 16, core.crc(backup[:92]))
        put(self.path, (sectors - 33) * 512, raw_array)
        put(self.path, end - 512, backup)
        return mbr + primary + raw_array

    def test_valid_backup_gpt_destroyed_primary_reconstruction(self):
        self.install_gpt()
        self.assertIsNotNone(core.gpt_read(self.path, os.path.getsize(self.path)))
        self.assertIsNone(core.gpt_read(self.path, os.path.getsize(self.path), True))
        self.install_descriptor()
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertEqual([], plan.blockers)
        self.assertEqual(['GPT'], [a['structural_oracle'] for a in plan.actions])
        records, _ = core.execute_plan(plan, self.work, self.gate, True)
        self.assertTrue(core.verify_gpt(self.path, os.path.getsize(self.path))['ok'])
        core.rollback(self.work, records[0]['transaction_id'], self.gate, True)
        self.assertIsNone(core.gpt_read(self.path, os.path.getsize(self.path), True))

    def test_gpt_bad_crc_not_trusted(self):
        self.install_gpt()
        put(self.path, os.path.getsize(self.path) - 512 + 56, b'X')
        self.assertIsNone(core.gpt_read(self.path, os.path.getsize(self.path)))

    def test_gpt_partition_array_bad_crc_rejected(self):
        self.install_gpt()
        put(self.path, os.path.getsize(self.path) - 33 * 512 + 64, b'X')
        self.assertIsNone(core.gpt_read(self.path, os.path.getsize(self.path)))

    def test_full_fingerprint_optional(self):
        fingerprint = core.fingerprint(self.path, True)
        self.assertEqual(core.file_hash(self.path), fingerprint['full_sha256'])

    def test_production_reference_real_boundary_end_to_end(self):
        # Execute the whole unchanged reference with only its unconditional
        # entry-point call removed. Never call its destructive repair helpers.
        reference = pathlib.Path(__file__).parent / 'reference_babuk_recover.py.txt'
        tree = ast.parse(reference.read_text(encoding='utf-8'))
        tree.body = [node for node in tree.body if not (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Name) and node.value.func.id == 'main')]
        namespace = {'__name__': 'regression_reference'}
        exec(compile(tree, str(reference), 'exec'), namespace)
        with open(self.path, 'r+b') as handle:
            handle.truncate(540 * 1024 * 1024)
        self.size = 536 * 1024 * 1024
        mft = (530 * 1024 * 1024 - self.start) // 4096
        mirror = (532 * 1024 * 1024 - self.start) // 4096
        self.sector = boot(self.start, self.size, mft, mirror)
        put(self.path, self.start, b'\0' * 512)
        # Remove the old, smaller backup from the resized fixture.
        put(self.path, self.start + 4 * 1024 * 1024 - 512, b'\0' * 512)
        put(self.path, self.start + self.size - 512, self.sector)
        for i in range(8):
            put(self.path, self.start + mft * 4096 + i * 1024, record(i))
        put(self.path, self.start + mirror * 4096, record())
        original = self.path + '.babyk'
        os.rename(self.path, original)
        with open(original, 'ab') as handle:
            handle.write(b'T' * 64)
        baseline = namespace['analyse'](original, 1)
        self.assertEqual('REPAIRABLE', baseline['verdict'])
        self.assertEqual(64, baseline['tail_bytes'])
        self.assertEqual([self.start], [v['start'] for v in baseline['volumes']])
        self.assertEqual(8, baseline['volumes'][0]['records'])
        disk = core.DiskState(original)
        scan = core.scan_ntfs(disk, self.work, 1, lambda text: None)
        diagnosis = core.diagnose(disk, scan)
        self.assertEqual([v['start'] for v in baseline['volumes']], [c.start for c in diagnosis.candidates])
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertEqual([], plan.blockers)
        records, final_path = core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(['PATCH', 'PATCH', 'TRUNCATE', 'RENAME', 'CREATE'], [r['operation_type'] for r in records])
        self.assertTrue(all(r['transaction_state'] == 'COMMITTED' for r in records))
        final = namespace['analyse'](final_path, 1)
        self.assertEqual('READY', final['verdict'])
        disk = core.DiskState(final_path)
        diagnosis = core.diagnose(disk, core.scan_ntfs(disk, self.work, 1, lambda text: None))
        again = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        self.assertEqual([], again.actions)
        self.assertEqual([], again.blockers)
        # Roll back the ENTIRE sequence in reverse order, including namespace
        # and size restoration, using recorded transaction IDs only.
        for transaction in reversed(records):
            core.rollback(self.work, transaction['transaction_id'], self.gate, True)
        self.assertTrue(os.path.exists(original))
        self.assertEqual(540 * 1024 * 1024 + 64, os.path.getsize(original))
        self.assertEqual(b'\0' * 512, core.read_at(original, self.start, 512))

    def test_discovery_vm_grouping_and_babuk_names(self):
        ds_root = os.path.join(self.root, 'datastores')
        folder = os.path.join(ds_root, 'store', 'machine')
        os.makedirs(folder)
        for name in ('machine-flat.vmdk.babyk', 'machine-sesparse.vmdk.babyk',
                     'machine-000001-delta.vmdk.babyk', 'machine-ctk.vmdk'):
            with open(os.path.join(folder, name), 'wb') as handle:
                handle.write(b'\0' * 512)
        machines = cli.discover(ds_root)
        self.assertEqual(1, len(machines))
        self.assertEqual(3, len(next(iter(machines.values()))['disks']))

    def test_invalid_gpt_signature_does_not_downgrade_to_mbr(self):
        self.install_gpt()
        put(self.path, os.path.getsize(self.path) - 512 + 56, b'X')
        disk, diagnosis = self.diagnosis()
        self.assertIn('BLOCKED_INSUFFICIENT_EVIDENCE', diagnosis.blockers)

    def test_source_record_change_rechecked_before_write(self):
        put(self.path, self.start, b'\0' * 512)
        disk, diagnosis = self.diagnosis()
        plan = core.plan_repair(disk, diagnosis, self.environment, 'lsilogic')
        old_stat = os.stat(self.path)
        put(self.path, self.start + 4 * 4096, record(9))
        # Even with preserved modification time and outside the cheap sample
        # positions, the evidence oracle must independently detect the change.
        os.utime(self.path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
        with self.assertRaises(core.RecoveryError):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_primary_only_gpt_blocked_conservatively(self):
        blob = self.install_gpt()
        put(self.path, 0, blob)
        put(self.path, os.path.getsize(self.path) - 512, b'\0' * 512)
        disk, diagnosis = self.diagnosis()
        self.assertEqual('GPT_PRIMARY_ONLY', diagnosis.table)
        self.assertIn('BLOCKED_INSUFFICIENT_EVIDENCE', diagnosis.blockers)

    def test_backup_corruption_after_prepare_blocks_first_write(self):
        def fault(state, transaction):
            if state == 'JOURNAL_PREPARED':
                put(transaction.record['backup_path'], 0, b'X')
        with self.assertRaisesRegex(core.RecoveryError, 'BACKUP_FAILURE'):
            self.transaction(fault)
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_interrupt_before_backup_has_safe_noop_rollback(self):
        def fault(state, transaction):
            if state == 'PLANNED':
                raise SimulatedCrash()
        with self.assertRaises(SimulatedCrash):
            self.transaction(fault)
        journal = self.journal()
        result = core.rollback(self.work, journal['transaction_id'], self.gate, True)
        self.assertTrue(result['no_mutation_required'])
        self.assertEqual('ROLLED_BACK_VERIFIED', result['transaction_state'])

    def test_second_write_gate_refusal_after_journal(self):
        def fault(state, transaction):
            if state == 'JOURNAL_PREPARED':
                transaction.gate.use_probe = lambda path, env: (_ for _ in ()).throw(
                    core.RecoveryError('SOURCE_IN_USE', 'VM started during preparation'))
        with self.assertRaisesRegex(core.RecoveryError, 'SOURCE_IN_USE'):
            self.transaction(fault)
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_invalid_patch_length_zero_writes(self):
        plan = self.patch_plan(planned=self.sector + b'X')
        with self.assertRaisesRegex(core.RecoveryError, 'patch length'):
            core.execute_plan(plan, self.work, self.gate, True)
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))

    def test_write_failure_detected_with_durable_journal(self):
        plan = self.patch_plan()
        actual_open = open
        def fail(path, mode='r', *args, **kwargs):
            if path == self.path and mode == 'r+b':
                raise OSError('fixture write failure')
            return actual_open(path, mode, *args, **kwargs)
        with mock.patch('builtins.open', side_effect=fail):
            with self.assertRaisesRegex(core.RecoveryError, 'WRITE_FAILURE'):
                core.execute_plan(plan, self.work, self.gate, True)
        journal = self.journal()
        self.assertEqual('ROLLBACK_REQUIRED', journal['transaction_state'])
        self.assertEqual(b'\0' * 512, core.read_at(self.path, self.start, 512))
        core.rollback(self.work, journal['transaction_id'], self.gate, True)

    def test_rename_crash_between_link_and_unlink_can_rollback(self):
        original = self.path + '.babyk'
        os.rename(self.path, original)
        plan = core.RepairPlan(core.DiskState(original))
        plan.add('RENAME', 0, b'', b'', self.candidate().evidence, 'IDENTITY', 'fixture',
                 dict(destination=self.path), destination=self.path)
        actual = os.unlink
        def crash(path, *args, **kwargs):
            if path == original:
                raise SimulatedCrash()
            return actual(path, *args, **kwargs)
        with mock.patch.object(os, 'unlink', side_effect=crash):
            with self.assertRaises(SimulatedCrash):
                core.execute_plan(plan, self.work, self.gate, True)
        self.assertTrue(os.path.samefile(original, self.path))
        core.rollback(self.work, self.journal()['transaction_id'], self.gate, True)
        self.assertTrue(os.path.exists(original))
        self.assertFalse(os.path.exists(self.path))

    def test_rollback_failure_classification_persisted(self):
        transaction = self.transaction()
        put(self.path, self.start, b'X')
        with self.assertRaises(core.RecoveryError):
            core.rollback(self.work, transaction['transaction_id'], self.gate, True)
        self.assertEqual('ROLLBACK_SOURCE_STATE_CHANGED', self.journal()['rollback_failure_classification'])

    def test_conflicting_primary_backup_gpt_blocks_writes(self):
        blob = self.install_gpt()
        primary = bytearray(blob[512:1024])
        primary[56:72] = b'\x09' * 16
        struct.pack_into('<I', primary, 16, 0)
        struct.pack_into('<I', primary, 16, core.crc(primary[:92]))
        put(self.path, 0, blob[:512] + primary + blob[1024:])
        disk, diagnosis = self.diagnosis()
        self.assertIn('BLOCKED_CONFLICTING_EVIDENCE', diagnosis.blockers)

    def test_gpt_overlapping_partitions_rejected_with_correct_crcs(self):
        self.install_gpt()
        end = os.path.getsize(self.path)
        array = bytearray(core.read_at(self.path, end - 33 * 512, 128 * 128))
        array[128:256] = array[:128]
        array[144:160] = b'\x05' * 16
        put(self.path, end - 33 * 512, array)
        header = bytearray(core.read_at(self.path, end - 512, 512))
        struct.pack_into('<I', header, 88, core.crc(array))
        struct.pack_into('<I', header, 16, 0)
        struct.pack_into('<I', header, 16, core.crc(header[:92]))
        put(self.path, end - 512, header)
        self.assertIsNone(core.gpt_read(self.path, end))

    def test_configuration_has_no_force_bypass(self):
        source = (pathlib.Path(__file__).parents[1] / 'babuk_recovery.py').read_text()
        self.assertNotIn("add_argument('--force'", source)
        self.assertNotIn("add_argument('--skip-env'", source)

    def test_stale_oversized_backup_rejected_by_independent_next_volume(self):
        put(self.path, self.start, b'\0' * 512)
        second_start = 6 * 1024 * 1024
        second_size = 1024 * 1024
        second_boot = boot(second_start, second_size)
        put(self.path, second_start, second_boot)
        put(self.path, second_start + second_size - 512, second_boot)
        for i in range(8):
            put(self.path, second_start + 4 * 4096 + i * 1024, record(i))
        put(self.path, second_start + 20 * 4096, record())
        stale_size = 13 * 512 * 1024
        put(self.path, self.start + stale_size - 512, boot(self.start, stale_size))
        disk, diagnosis = self.diagnosis()
        self.assertEqual([], diagnosis.blockers)
        self.assertEqual([self.start, second_start], [c.start for c in diagnosis.candidates])
        self.assertTrue(any(c.size == stale_size and 'overlaps independent' in c.reason for c in diagnosis.rejected))

    def test_scan_checkpoint_resumes_after_interruption(self):
        disk = core.DiskState(self.path)
        actual = core.atomic_json
        def interrupted(path, value):
            actual(path, value)
            if 'checkpoints' in path and not value.get('complete'):
                raise SimulatedCrash()
        with mock.patch.object(core, 'atomic_json', side_effect=interrupted):
            with self.assertRaises(SimulatedCrash):
                core.scan_ntfs(disk, self.work, 1, lambda text: None)
        # The last fsynced window is resumed, not silently scanned against a
        # different file or discarded as a global no-hit conclusion.
        resumed = core.scan_ntfs(disk, self.work, 1, lambda text: None)
        self.assertTrue(resumed['complete'])
        self.assertEqual(disk.fingerprint, resumed['fingerprint'])
        self.assertEqual(2, len(resumed['hits']))

    def test_production_python35_syntax_compatibility(self):
        for name in ('recovery_core.py', 'babuk_recovery.py', 'legacy_readonly.py'):
            source = (pathlib.Path(__file__).parents[1] / name).read_text(encoding='utf-8')
            ast.parse(source, filename=name, feature_version=(3, 5))

    def test_packaged_reference_matches_historical_tool(self):
        historical = pathlib.Path(__file__).parents[2] / 'tools' / 'babuk_recover.py'
        if historical.exists():
            packaged = pathlib.Path(__file__).parent / 'reference_babuk_recover.py.txt'
            self.assertEqual(historical.read_bytes(), packaged.read_bytes())

    def test_workspace_placeholder_is_not_an_unfinished_transaction(self):
        with open(os.path.join(self.work.path, 'transactions', '.gitkeep'), 'w') as handle:
            handle.write('')
        self.assertEqual([], self.work.incomplete())
        self.assertEqual('COMMITTED', self.transaction()['transaction_state'])

    def test_full_hash_mode_retained_across_transaction(self):
        plan = self.patch_plan()
        plan.disk.fingerprint = core.fingerprint(self.path, True)
        records, _ = core.execute_plan(plan, self.work, self.gate, True)
        self.assertIn('full_sha256', records[0]['source_fingerprint'])
        self.assertEqual(core.file_hash(self.path), records[0]['post_fingerprint']['full_sha256'])

    def test_oversized_descriptor_blocked_without_unbounded_read(self):
        descriptor = self.install_descriptor()
        with open(descriptor, 'ab') as handle:
            handle.truncate(2 * 1024 * 1024)
        self.assertFalse(core.descriptor_check(descriptor, self.path, os.path.getsize(self.path))['ok'])


if __name__ == '__main__':
    unittest.main()
