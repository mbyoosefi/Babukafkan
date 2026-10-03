#!/usr/bin/env python3
"""Production-reference-preserving Babuk recovery entry point."""
from __future__ import print_function
import argparse
import os
import sys
import uuid

if sys.version_info < (3, 5):
    sys.stderr.write('Babuk Recovery requires Python 3.5 or newer. Use the ESXi python3 interpreter.\n')
    sys.exit(2)

import legacy_readonly as legacy
import recovery_core as core


def discover(root):
    machines = {}
    for datastore in legacy.find_datastores(root):
        for name, vm in legacy.find_disks(datastore['path']).items():
            key = datastore['name'] + '/' + os.path.relpath(vm['dir'], datastore['path'])
            machines[key] = vm
        # Sparse/delta extents must appear in reports even though never patched.
        for directory, dirs, names in os.walk(datastore['path']):
            for name in names:
                lower = name.lower()
                if '-delta.vmdk' in lower and lower.endswith(('.vmdk', '.babyk')):
                    key = datastore['name'] + '/' + os.path.relpath(directory, datastore['path'])
                    vm = machines.setdefault(key, dict(name=os.path.basename(directory), dir=directory, disks=[]))
                    path = os.path.join(directory, name)
                    if path not in vm['disks']:
                        vm['disks'].append(path)
    return machines


def write_report(workspace, report):
    base = os.path.join(workspace.path, 'reports', report['run_id'])
    core.immutable(base + '.json', core.json_bytes(report))
    lines = ['Babuk Recovery ' + core.VERSION, 'Run ' + report['run_id'], report['timestamp']]
    for source in report['source_disks']:
        lines.append('%s: %s' % (source['path'], source['final_verdict']))
        for blocker in source.get('repair_plan', {}).get('blockers', []):
            lines.append('  BLOCKED: ' + blocker)
        for rejected in source.get('diagnosis', {}).get('rejected_candidates', []):
            lines.append('  REJECTED @%d: %s' % (rejected['sector_offset'], rejected['reason']))
        for transaction in source.get('transactions', []):
            lines.append('  transaction %s %s' % (transaction['transaction_id'], transaction['transaction_state']))
    core.immutable(base + '.txt', ('\n'.join(lines) + '\n').encode('utf-8'))
    core.immutable(os.path.join(workspace.path, 'logs', report['run_id'] + '.log'),
                   ('\n'.join(lines) + '\n').encode('utf-8'))
    core.atomic_json(os.path.join(workspace.path, 'state', 'latest_run.json'), report)
    print('Report: ' + base + '.json')


def analyze(path, workspace, environment, tail, full, adapter):
    disk = core.DiskState(path, full)
    if environment.get('write_capable'):
        core.source_use(disk.path, environment)
    layout = core.topology(disk.path)
    if not layout['ok']:
        return dict(path=disk.path, source_fingerprint=disk.fingerprint, layout=layout,
                    final_verdict=layout['state'], transactions=[]), None
    scanned = core.scan_ntfs(disk, workspace, tail)
    diagnosis = core.diagnose(disk, scanned)
    plan = core.plan_repair(disk, diagnosis, environment, adapter)
    source = dict(path=disk.path, source_fingerprint=disk.fingerprint, layout=layout,
                  diagnosis=diagnosis.to_dict(), repair_plan=plan.to_dict(), transactions=[],
                  final_verdict=plan.verdict, scan_scope=scanned['regions'],
                  rejected_signature_candidates=scanned['rejected'],
                  rollback_availability='transaction-specific verified backup after authorization')
    if not plan.actions and not plan.blockers:
        checks = [core.ntfs_checks(path, c, True) for c in diagnosis.candidates]
        desc = core.descriptor_path(path)
        descriptor = core.descriptor_check(desc, path, disk.data_end, environment.get('vmkfstools')) if desc else None
        source['structural_verification'] = checks
        source['semantic_verification'] = descriptor
        if not all(c['ok'] for c in checks) or not descriptor or not descriptor['ok']:
            source['final_verdict'] = 'BLOCKED_INSUFFICIENT_EVIDENCE'
        elif not descriptor['semantic']['available']:
            source['final_verdict'] = 'RECOVERY_PARTIAL'
        elif not descriptor['semantic']['ok']:
            source['final_verdict'] = 'BLOCKED_UNSUPPORTED_VMDK_LAYOUT'
    if workspace.incomplete(disk.path):
        source['unfinished_transactions'] = workspace.incomplete(disk.path)
        source['final_verdict'] = 'FAILED_TRANSACTION'
        plan.blockers.append('FAILED_TRANSACTION')
    cache = dict(tool_version=core.VERSION, fingerprint=disk.fingerprint, diagnosis=diagnosis.to_dict(),
                 repair_plan=plan.to_dict(), timestamp=core.timestamp())
    if core.fingerprint(disk.path, full) != disk.fingerprint:
        raise core.RecoveryError('SOURCE_CHANGED', 'source changed during diagnosis/planning')
    core.atomic_json(os.path.join(workspace.path, 'state', core.sha(disk.path.encode('utf-8')) + '.json'), cache)
    return source, plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--analyze', action='store_true', help='read-only batch diagnosis')
    mode.add_argument('--dry-run', action='store_true', help='read-only exact repair planning')
    mode.add_argument('--repair', action='store_true', help='execute authorized plan')
    mode.add_argument('--rollback', metavar='TRANSACTION_ID')
    mode.add_argument('--report', action='store_true', help='display persisted latest report')
    mode.add_argument('--self-test', action='store_true')
    mode.add_argument('--check-transactions', action='store_true', help='read-only journal inspection')
    parser.add_argument('--source', action='append', default=[], help='base-flat extent, repeatable')
    parser.add_argument('--root', default='/vmfs/volumes')
    parser.add_argument('--work-dir', default=os.path.dirname(os.path.realpath(__file__)))
    parser.add_argument('--tail', type=int, default=2048)
    parser.add_argument('--full-hash', action='store_true')
    parser.add_argument('--adapter', choices=('lsilogic', 'buslogic', 'ide', 'pvscsi'))
    parser.add_argument('--authorize-repair', action='store_true')
    parser.add_argument('--authorize-rollback', action='store_true')
    args = parser.parse_args(argv)
    if args.tail < 0:
        parser.error('--tail must be nonnegative')
    if args.self_test:
        import unittest
        suite = unittest.defaultTestLoader.discover(os.path.join(os.path.dirname(__file__), 'tests'))
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    workspace = core.Workspace(args.work_dir)
    if args.report:
        report = core.load_json(os.path.join(workspace.path, 'state', 'latest_run.json'))
        print(core.json_bytes(report).decode('utf-8'))
        return 0
    if args.check_transactions:
        records = workspace.incomplete()
        print(core.json_bytes(dict(unfinished_transactions=records)).decode('utf-8'))
        print('DONE/CHECKED')
        return 2 if records else 0
    environment = core.preflight()
    gate = core.WriteGate(environment)
    if args.rollback:
        record = core.rollback(workspace, args.rollback, gate, args.authorize_rollback)
        print(record['transaction_state'])
        write_report(workspace, dict(run_id=uuid.uuid4().hex, tool_version=core.VERSION,
                     timestamp=core.timestamp(), environment=environment, vmware_host_details=environment['esxi'],
                     source_disks=[dict(path=record['source_path'], source_fingerprint=record['source_fingerprint'],
                                        transactions=[record], final_verdict=record['transaction_state'])],
                     discovered_vm_relationships={}, final_verdict=record['transaction_state']))
        return 0
    if args.repair and not args.authorize_repair:
        parser.error('--repair requires --authorize-repair; missing input is not consent')
    report = dict(run_id=uuid.uuid4().hex, tool_version=core.VERSION, timestamp=core.timestamp(),
                  environment=environment, vmware_host_details=environment['esxi'], source_disks=[],
                  discovered_vm_relationships={}, final_verdict='UNKNOWN')
    machines = {} if args.source else discover(args.root)
    report['discovered_vm_relationships'] = machines
    paths = sorted(set(args.source or [p for vm in machines.values() for p in vm['disks']]))
    interactive = not (args.analyze or args.dry_run or args.repair)
    for index, path in enumerate(paths, 1):
        print('[%d/%d] %s' % (index, len(paths), path))
        source, plan = None, None
        try:
            source, plan = analyze(path, workspace, environment, args.tail, args.full_hash, args.adapter)
            print(source['final_verdict'])
            authorized = args.repair and args.authorize_repair
            if interactive and plan and plan.actions and not plan.blockers:
                print(core.json_bytes(plan.to_dict()).decode('utf-8'))
                choice = legacy.ask('Repair this disk?', ['y', 'n', 'q'], 'n')
                if choice == 'q':
                    report['source_disks'].append(source)
                    break
                authorized = choice == 'y'
            if authorized and plan:
                if not environment['write_capable']:
                    raise core.RecoveryError('ENVIRONMENT', 'production writes require ESXi and native lock tooling')
                for action in plan.actions:
                    action['run_id'] = report['run_id']
                records, final_path = core.execute_plan(plan, workspace, gate, True)
                source['transactions'], source['final_path'] = records, final_path
                source['readback_results'] = [r['sha256_after'] for r in records]
                source['structural_verification'] = [r['verification_results']['structural'] for r in records]
                source['semantic_verification'] = [r['verification_results']['semantic'] for r in records]
                # Final whole-plan oracle catches relationships that individual
                # transaction checks cannot establish on their own.
                final_source, final_plan = analyze(final_path, workspace, environment, args.tail, args.full_hash, args.adapter)
                source['final_verification'] = final_source
                source['final_verdict'] = ('RECOVERED_VERIFIED' if final_source['final_verdict'] == 'HEALTHY_VERIFIED'
                                          and all(r['transaction_state'] == 'COMMITTED' for r in records)
                                          else 'RECOVERY_PARTIAL')
        except Exception as error:
            classification = error.classification if isinstance(error, core.RecoveryError) else 'INSUFFICIENT_EVIDENCE'
            source = source or dict(path=path, transactions=[])
            source.update(error=str(error), failure_classification=classification,
                          final_verdict={'ENVIRONMENT': 'FAILED_ENVIRONMENT_GATE',
                                         'SOURCE_IN_USE': 'BLOCKED_SOURCE_IN_USE',
                                         'INSUFFICIENT_EVIDENCE': 'BLOCKED_INSUFFICIENT_EVIDENCE',
                                         'CONFLICTING_EVIDENCE': 'BLOCKED_CONFLICTING_EVIDENCE',
                                         'UNSUPPORTED_LAYOUT': 'BLOCKED_UNSUPPORTED_LAYOUT',
                                         'SOURCE_CHANGED': 'BLOCKED_CONFLICTING_EVIDENCE'}.get(classification, 'FAILED_TRANSACTION'))
            # Include durable records even when execution died before returning.
            source['transactions'] = []
            for name in os.listdir(os.path.join(workspace.path, 'transactions')):
                try:
                    record = core.load_transaction(os.path.join(workspace.path, 'transactions', name))
                    if record.get('run_id') == report['run_id'] or record['source_fingerprint']['path'] == os.path.realpath(path):
                        source['transactions'].append({k: v for k, v in record.items() if not k.startswith('_')})
                except Exception:
                    pass
            print(source['final_verdict'] + ': ' + str(error))
        report['source_disks'].append(source)
    verdicts = [s['final_verdict'] for s in report['source_disks']]
    report['final_verdict'] = (verdicts[0] if verdicts and len(set(verdicts)) == 1 else
                               'RECOVERY_PARTIAL' if verdicts else 'BLOCKED_INSUFFICIENT_EVIDENCE')
    write_report(workspace, report)
    print('DONE/CHECKED')
    return 0 if verdicts and all(v in ('HEALTHY_VERIFIED', 'RECOVERED_VERIFIED', 'DAMAGED_RECOVERABLE',
                                       'WRITE_READY_VERIFIED') for v in verdicts) else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except core.RecoveryError as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print('Interrupted; inspect durable transactions before continuing.', file=sys.stderr)
        sys.exit(130)
