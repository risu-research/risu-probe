"""Bounded stdio subprocess lifecycle for Windows and POSIX MCP tool servers."""
from __future__ import annotations
import os
import queue
import signal
import subprocess
import threading

MAX_REQUEST_BYTES = 1_048_576


def spawn_stdio(argv, *, env=None):
    options = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL, text=True,
                   encoding='utf-8', errors='replace', bufsize=1, env=env)
    if os.name == 'nt':
        options['creationflags'] = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    else:
        options['start_new_session'] = True
    return subprocess.Popen(argv, **options)


def write_with_timeout(proc, value, timeout):
    if proc is None or proc.poll() is not None or not proc.stdin:
        raise BrokenPipeError('MCP server already exited')
    if len(value.encode('utf-8')) > MAX_REQUEST_BYTES:
        raise ValueError('MCP request exceeds 1 MiB output budget')
    if timeout <= 0:
        raise TimeoutError('MCP request deadline elapsed')
    result = queue.Queue(maxsize=1)
    def writer():
        try:
            proc.stdin.write(value)
            proc.stdin.flush()
            result.put(None)
        except (OSError, ValueError) as exc:
            result.put(exc)
    threading.Thread(target=writer, name='risu-mcp-stdin', daemon=True).start()
    try:
        outcome = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise TimeoutError('MCP subprocess refused stdin data') from exc
    if outcome is not None:
        raise outcome


def stop_stdio(proc):
    """Stop the server and descendants; bounded best effort on Windows."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            if os.name == 'nt':
                try:
                    subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=3, check=False,
                                   creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                except (OSError,subprocess.TimeoutExpired):
                    proc.terminate()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                if os.name != 'nt':
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
    finally:
        for handle in (proc.stdin, proc.stdout):
            try:
                if handle and not handle.closed:
                    handle.close()
            except (OSError,ValueError,BrokenPipeError):
                pass
