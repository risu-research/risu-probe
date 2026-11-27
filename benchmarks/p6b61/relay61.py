"""Root fixture relay; trusted handler runs under separate UID; captures native frames."""
import pathlib,subprocess,sys,threading,os
base=pathlib.Path(sys.argv[1]);name=sys.argv[2];d=base/name
p=subprocess.Popen([sys.executable,str(base/'code'/'handler61.py'),str(base/'handler'/(name+'.json'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,user=65533,group=65533,extra_groups=[],cwd=base)
def pump():
    try:
        with (d/'ingress.jsonl').open('ab') as f:
            for line in sys.stdin.buffer:
                f.write(line);f.flush();p.stdin.write(line);p.stdin.flush()
    except BrokenPipeError:pass
    finally:
        try:p.stdin.close()
        except OSError:pass
threading.Thread(target=pump,daemon=True).start()
with (d/'reply.jsonl').open('ab') as f:
    for line in p.stdout:
        f.write(line);f.flush();sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
rc=p.wait();(d/'exit.txt').write_text(str(rc));sys.exit(rc)
