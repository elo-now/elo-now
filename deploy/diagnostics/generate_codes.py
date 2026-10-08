"""Generate the public diagnostic vocabulary from application source files."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]

def vocabulary():
    src = ROOT / 'apps/desktop/src-tauri'
    library = (src / 'src/lib.rs').read_text()
    operations = library.split('fn application_operation(op: &str) -> bool {', 1)[1].split('\n}', 1)[0]
    return {
        'ui': sorted(set(re.findall(r'"([A-Za-z0-9_.:-]+)":', (ROOT / 'apps/desktop/src/locales/en.ts').read_text()))),
        'core': sorted(set(re.findall(r'"([A-Za-z0-9_.:-]+)"', operations))),
        'ipc': sorted(set(re.findall(r'"([A-Za-z0-9_.:-]+)",', (src / 'build.rs').read_text()))),
        'session': sorted(set(re.findall(r'c"([A-Za-z0-9_.:-]+)"', '\n'.join((src / 'src' / name).read_text() for name in ['native_session.rs', 'native_session/group.rs', 'native_media.rs'])))),
        'call': ['idle', 'connecting', 'connected', 'reconnecting'],
        'runtime': ['started', 'javascript_error', 'unhandled_rejection', 'react_error'],
        'test': ['diagnostics_test'],
        'media': ['system_call_start', 'group_start', 'group_update', 'group_reset', 'start', 'update', 'stop', 'poll', 'signal', 'timeout', 'native_failure'],
    }

if __name__ == '__main__':
    (Path(__file__).parent / 'codes.json').write_text(json.dumps(vocabulary(), indent=2) + '\n')
