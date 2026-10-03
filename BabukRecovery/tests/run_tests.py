"""Record clean regression output and a machine-readable summary."""
import io
import json
import pathlib
import sys
import time
import unittest

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
started = time.monotonic()
output = io.StringIO()
suite = unittest.defaultTestLoader.discover(str(root / 'tests'))
result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
duration = time.monotonic() - started
(root / 'tests' / 'RESULTS.txt').write_text(output.getvalue(), encoding='utf-8')
summary = dict(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
               skipped=len(result.skipped), elapsed_seconds=round(duration, 3),
               success=result.wasSuccessful(), python=sys.version,
               scope='synthetic fixtures only; no live ESXi/media validation',
               timestamp_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
(root / 'tests' / 'RESULTS.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps(summary))
if not result.wasSuccessful():
    print(output.getvalue())
sys.exit(0 if result.wasSuccessful() else 1)
