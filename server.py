#!/usr/bin/env python3
import json
import os
import plistlib
from functools import lru_cache
import secrets
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
CHILDREN = []



@lru_cache(maxsize=256)
def app_from_path(executable):
    # The outermost bundle identifies the app, rather than its nested helpers.
    for part in Path(executable).parents:
        if part.suffix.lower() == '.app':
            bundle = part
    if 'bundle' not in locals():
        return None
    name = bundle.stem
    try:
        with (bundle / 'Contents' / 'Info.plist').open('rb') as f:
            info = plistlib.load(f)
        name = info.get('CFBundleDisplayName') or info.get('CFBundleName') or name
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    return str(name), str(bundle)


def ownership(p):
    if p.pid == os.getpid():
        return dict(app_name='本机服务管理台', app_source='本服务', app_path=str(ROOT))
    # Prefer the process's own bundle, then inspect its parent chain.
    current = p
    for depth in range(20):
        if current is None or current.pid <= 1:
            break
        try:
            found = app_from_path(current.exe())
            if found:
                return dict(app_name=found[0], app_source='应用路径' if depth == 0 else '父进程归属', app_path=found[1])
            current = current.parent()
        except (psutil.Error, OSError):
            break
    try:
        executable = p.exe()
        if executable.startswith(('/System/', '/usr/libexec/', '/usr/sbin/')):
            return dict(app_name='macOS 系统服务', app_source='系统路径', app_path=executable)
    except psutil.Error:
        pass
    return dict(app_name='独立服务 / 未识别应用', app_source='未找到应用归属', app_path='')


def services():
    rows, denied = [], 0
    protected = {os.getpid(), *(p.pid for p in psutil.Process().parents())}
    for p in psutil.process_iter():
        try:
            listeners = [c for c in p.net_connections(kind='tcp') if c.status == psutil.CONN_LISTEN]
            if not listeners:
                continue
            def read(fn, default):
                try:
                    return fn()
                except (psutil.Error, OSError):
                    return default
            argv = read(p.cmdline, [])
            rows.append(dict(**ownership(p), pid=p.pid, created=p.create_time(), name=p.name(),
                             executable=read(p.exe, ''), cwd=read(p.cwd, ''),
                             command=argv, user=read(p.username, ''),
                             addresses=sorted({f'{c.laddr.ip}:{c.laddr.port}' for c in listeners}),
                             ports=sorted({c.laddr.port for c in listeners}),
                             protected=p.pid in protected))
        except psutil.AccessDenied:
            denied += 1
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass
    return dict(services=sorted(rows, key=lambda r: (r['ports'][0], r['pid'])), denied=denied)


def operate(item, action):
    pid = int(item['pid'])
    protected = {os.getpid(), *(p.pid for p in psutil.Process().parents())}
    if pid in protected or pid <= 1:
        raise ValueError('此进程受保护，不能操作')
    p = psutil.Process(pid)
    if abs(p.create_time() - float(item['created'])) > .001:
        raise ValueError('进程已发生变化，请刷新后重试')
    if not any(c.status == psutil.CONN_LISTEN for c in p.net_connections(kind='tcp')):
        raise ValueError('此进程已不再监听端口，请刷新')
    argv, cwd, env = None, None, None
    if action == 'restart':
        argv, cwd, env = p.cmdline(), p.cwd(), p.environ()
        if not argv or not cwd or not os.path.isdir(cwd):
            raise ValueError('无法获取完整启动信息，未执行关闭')
    p.terminate()
    try:
        p.wait(timeout=4)
    except psutil.TimeoutExpired:
        p.kill()
        p.wait(timeout=3)
    if action == 'restart':
        logdir = ROOT / 'logs'
        logdir.mkdir(exist_ok=True)
        with (logdir / f'restart-{pid}.log').open('ab') as logfile:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=logfile, stderr=logfile, start_new_session=True)
        CHILDREN.append(child)
        time.sleep(.7)
        if child.poll() is not None:
            raise ValueError(f'原进程已关闭，但新进程已退出（{child.returncode}），请查看 logs/restart-{pid}.log')
        return f'已重新启动，新 PID：{child.pid}；端口状态请以刷新结果为准'
    return '已关闭进程及其占用的所有端口'


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value, content_type='application/json; charset=utf-8'):
        data = value.encode() if isinstance(value, str) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get('Host') in ('127.0.0.1:9990', 'localhost:9990')

    def do_GET(self):
        if not self.valid_host():
            return self.reply(403, {'error': '无效访问来源'})
        if self.path == '/':
            return self.reply(200, (ROOT / 'index.html').read_text().replace('__TOKEN__', TOKEN), 'text/html; charset=utf-8')
        if self.path == '/api/services':
            return self.reply(200, services())
        self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.valid_host() or self.headers.get('X-Token') != TOKEN:
            return self.reply(403, {'error': '无效访问来源，请刷新页面'})
        if self.path != '/api/action':
            return self.reply(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                raise ValueError('请求大小不正确')
            body = json.loads(self.rfile.read(length))
            action, items = body['action'], body['items']
            if action not in ('stop', 'restart') or not isinstance(items, list) or not 1 <= len(items) <= 100:
                raise ValueError('操作参数不正确')
            results = []
            with LOCK:
                seen = set()
                for item in items:
                    pid = item['pid']
                    if pid in seen:
                        continue
                    seen.add(pid)
                    try:
                        results.append(dict(pid=pid, ok=True, message=operate(item, action)))
                    except (psutil.Error, OSError, ValueError, KeyError, TypeError) as exc:
                        results.append(dict(pid=pid, ok=False, message=str(exc) or type(exc).__name__))
                CHILDREN[:] = [p for p in CHILDREN if p.poll() is None]
            self.reply(200, {'results': results})
        except (ValueError, KeyError, TypeError) as exc:
            self.reply(400, {'error': str(exc)})


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 9990), Handler)
    print('服务管理台 http://127.0.0.1:9990', flush=True)
    server.serve_forever()
