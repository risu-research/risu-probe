"""Best-effort tracked-file hygiene gate for PUBLIC CI (not a secret guarantee)."""
from pathlib import Path
import re,subprocess
ROOT=Path(__file__).resolve().parents[1]
DENY=('.zip','.sqlite','.db','.p12','.pfx','.pem','.key','.env','.jsonl','.log','.tar.gz','.whl')
PATTERNS={
 'private_key':rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
 'github_token':rb'gh[pousr]_[A-Za-z0-9_]{25,}',
 'aws_access_key':rb'AKIA[0-9A-Z]{16}',
 'api_key':rb'sk-(?:proj-)?[A-Za-z0-9_-]{30,}',
 'embedded_password':rb'https?://[^/:\s@]{1,60}:[^/@\s]{5,80}@',
}
def audit():
 proc=subprocess.run(['git','ls-files','-z'],cwd=ROOT,capture_output=True,check=True)
 paths=[part.decode('utf-8') for part in proc.stdout.split(b'\0') if part]
 errors=[]
 for rel in paths:
  p=ROOT/rel
  if not p.is_file():errors.append((rel,'tracked file missing'));continue
  raw=p.read_bytes()
  if len(raw)>600_000:errors.append((rel,'oversized tracked source'))
  if rel.lower().endswith(DENY) or '/.env' in rel:errors.append((rel,'blocked public artifact extension'))
  if b'\0' in raw:errors.append((rel,'binary file in public product'))
  for kind,pattern in PATTERNS.items():
   if re.search(pattern,raw):errors.append((rel,'possible secret pattern: '+kind))
  if rel.startswith('src/') and rel.endswith('.py') and b'\r\n' in raw:
   errors.append((rel,'source must preserve canonical LF'))
 if sum(p.startswith('src/') and p.endswith('.py') for p in paths)<38:
  errors.append(('src','module removal requires review'))
 if errors:raise SystemExit('PUBLIC_SOURCE_HYGIENE_REQUIRES_REVIEW '+repr(errors))
 print('PUBLIC_SOURCE_HYGIENE_PASS',len(paths),'tracked files (heuristic only)')
if __name__=='__main__':audit()
