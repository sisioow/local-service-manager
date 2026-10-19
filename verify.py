import subprocess
import sys
import time
import psutil
import server

child = subprocess.Popen([sys.executable, '-m', 'http.server', '19990', '--bind', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(.5)
    row = next(r for r in server.services()['services'] if r['pid'] == child.pid)
    assert 19990 in row['ports'] and row['cwd'] and row['command']
    message = server.operate(row, 'restart')
    new_child = server.CHILDREN[-1]
    time.sleep(.3)
    new_row = next(r for r in server.services()['services'] if r['pid'] == new_child.pid)
    assert 19990 in new_row['ports']
    server.operate(new_row, 'stop')
    assert not psutil.pid_exists(new_child.pid)
    try:
        server.operate({'pid': __import__('os').getpid(), 'created': 0}, 'stop')
        raise AssertionError('self protection failed')
    except ValueError:
        pass
    print('PASS: discovery, restart, stop, self protection')
finally:
    for p in [child, *server.CHILDREN]:
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=5)
