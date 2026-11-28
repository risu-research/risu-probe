"""B63 broker: gate owner UID only; trusted handler or root control."""
import sys,os,pathlib,socket,socketserver,struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gate64 as G
import lifecycle as L
def call(path,req):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(15);s.connect(path);s.sendall(G.enc(req)+b'\n')
        with s.makefile('rb') as f:
            r=f.readline(131073)
            if not r:raise RuntimeError('BROKER_UNKNOWN')
            return G.parse(r)
def main():
    c=G.parse(pathlib.Path(sys.argv[1]).read_bytes());os.umask(0o077)
    gate=G.Gate(c['db'],c['trust'],Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['observer_key'])))
    class H(socketserver.StreamRequestHandler):
        def handle(self):
            uid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
            try:
                self.request.settimeout(10);raw=self.rfile.readline(131073)
                if len(raw)>131072 or not raw.endswith(b'\n'):raise ValueError('MALFORMED')
                req=G.parse(raw);kind=req['kind']
                if kind in ('admit','recover'):
                    if uid!=65533:raise ValueError('PEER_DENIED')
                    result=gate.admit(req['envelope'],req['observed'],req.get('ticket')) if kind=='admit' else gate.recover(req['query'])
                elif kind=='event':
                    b=L.verify(gate.lt,req['event'])
                    if uid!=(65533 if b['kind'] in ('START','STEP','FINISH') else 0):raise ValueError('PEER_DENIED')
                    result=gate.event(req['event'])
                elif kind=='seal':
                    if uid!=0:raise ValueError('PEER_DENIED')
                    result=gate.seal(req['seal'])
                else:raise ValueError('UNKNOWN')
                out=dict(ok=True,result=result)
            except (ValueError,KeyError,TypeError) as e:out=dict(ok=False,error=str(e))
            self.wfile.write(G.enc(out)+b'\n')
    with socketserver.UnixStreamServer(c['socket'],H) as s:
        os.chmod(c['socket'],0o666);s.serve_forever(poll_interval=.05)
if __name__=='__main__':main()
