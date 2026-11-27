"""B61 Unix socket wrapper around frozen B60. Separate ingress log, not atomic with events."""
import os,sys,socket,socketserver,struct,pathlib
from lifecycle import enc,parse,verify,execute,init
def log(c,x):
    with open(c['log'],'ab') as f:f.write(enc(x)+b'\n');f.flush();os.fsync(f.fileno())
def serve(cfg):
    c=parse(pathlib.Path(cfg).read_bytes());os.umask(0o077);init(c['db'],c['trust'])
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            uid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            self.request.settimeout(10)
            raw=self.rfile.readline(65537)
            e=None
            try:
                if len(raw)>65536 or not raw.endswith(b'\n'):raise ValueError('MALFORMED')
                e=parse(raw);b=verify(c['trust'],e)
                log(c,dict(stage='INGRESS',uid=uid,event=e))
                if (b['kind'] in ('START','STEP','FINISH') and uid!=65533) or (b['kind'] not in ('START','STEP','FINISH') and uid!=0):raise ValueError('PEER_DENIED')
                out=dict(ok=True,**execute(c['db'],c['trust'],e))
            except (ValueError,KeyError,TypeError) as ex:out=dict(ok=False,error=str(ex))
            log(c,dict(stage='DECISION',uid=uid,event=e,out=out))
            self.wfile.write(enc(out)+b'\n')
    with socketserver.UnixStreamServer(c['socket'],Handler) as s:
        os.chmod(c['socket'],0o666);s.serve_forever(poll_interval=.05)
def call(path,e):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(15);s.connect(path);s.sendall(enc(e)+b'\n')
        with s.makefile('rb') as f:
            raw=f.readline(65537)
            if not raw:raise RuntimeError('BROKER_UNKNOWN')
            return parse(raw)
if __name__=='__main__':serve(sys.argv[1])
