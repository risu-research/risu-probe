"""Raw stdio capture and actual OS separation; root fixture launcher only."""
import os, pathlib, subprocess, sys, threading
def main():
    base=pathlib.Path(sys.argv[1]); code=base/'code'
    p=subprocess.Popen([sys.executable,str(code/'handler.py'),str(base/'handler'/'config.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,user=65533,group=65533,extra_groups=[],cwd=base)
    def pump():
        try:
            with (base/'ingress.jsonl').open('ab') as f:
                for line in sys.stdin.buffer:
                    f.write(line);f.flush();p.stdin.write(line);p.stdin.flush()
        finally:
            p.stdin.close()
    threading.Thread(target=pump,daemon=True).start()
    with (base/'reply.jsonl').open('ab') as f:
        for line in p.stdout:
            f.write(line);f.flush();sys.stdout.buffer.write(line);sys.stdout.buffer.flush()
    sys.exit(p.wait())
if __name__=='__main__':main()
