"""B58 controlled Linux qualification against source-pinned external application."""
import concurrent.futures,hashlib,json,os,pathlib,shutil,sqlite3,subprocess,sys,tempfile,time,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from broker import enc,parse,DOMAIN,call
APP=65534; BROKER=65532
PINS={'library_toolkit/server.py':'f7b8f2e916f9df6409f83a2663a4d00d3d9061a0','library_toolkit/service.py':'8dcbc523ff94448f6a89dbf295a52c3a0d0f50b7','library_toolkit/catalog.json':'f87c53fe0b5cd08aa416513c9d8b01ab206c7b45'}
def blob(p):
    b=p.read_bytes();return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def read_db(p):
    if not p.exists():return dict(rows=[],receipts=[],ops=[])
    with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as db:
        tables={x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return dict(rows=[list(x) for x in db.execute('SELECT list_name,book_id,saved_at FROM reading_items ORDER BY list_name,book_id')] if 'reading_items'in tables else [],
          receipts=[parse(x[0]) for x in db.execute('SELECT result FROM receipts ORDER BY seq')] if 'receipts'in tables else [],
          ops=[list(x) for x in db.execute('SELECT op,winner,created,saved_at FROM operations ORDER BY op')] if 'operations'in tables else [])
def main(src,out):
    assert os.geteuid()==0,'root only for fixture process isolation'
    src=pathlib.Path(src).resolve();out=pathlib.Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='99ea07d1074eb06885ec1107029e48d83fe05e78'
    for p,h in PINS.items():assert blob(src/p)==h,p
    with tempfile.TemporaryDirectory(prefix='risu-b58-') as tmp:
        base=pathlib.Path(tmp);base.chmod(0o755)
        up=base/'upstream';shutil.copytree(src,up,ignore=shutil.ignore_patterns('.git','__pycache__','.env'))
        code=base/'code';code.mkdir(mode=0o755)
        for name in ('broker.py','worker.py'):shutil.copyfile(pathlib.Path(__file__).with_name(name),code/name)
        for p in up.rglob('*'):
            if p.is_dir():p.chmod(0o755)
            elif p.is_file():p.chmod(0o644)
        for p,h in PINS.items():assert blob(up/p)==h,p
        private=base/'protected';private.mkdir(mode=0o700);os.chown(private,BROKER,BROKER)
        sockdir=base/'socket';sockdir.mkdir(mode=0o755);os.chown(sockdir,BROKER,BROKER)
        baseline=base/'baseline';baseline.mkdir(mode=0o700);os.chown(baseline,APP,APP)
        db=private/'reading.sqlite3';sock=sockdir/'effect.sock';cfg=base/'broker.json'
        key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        scope='campusreads:'+uuid.uuid4().hex
        conf=dict(scope=scope,pub=pub,db=str(db),socket=str(sock),client_uid=APP,books=['B001','B002','B003','B004','B005','B006'],crash='none')
        (out/'trust.json').write_bytes(enc({k:conf[k] for k in ('scope','pub','client_uid','books')}))
        (out/'source-pins.json').write_bytes(enc(PINS))
        events=[];process=None;broker_logs=[]
        def child(book,list_name='demo'):return dict(book_id=book,list_name=list_name)
        def par(tool='plan_reading',args=None):return dict(tool=tool,arguments=args or dict(query='machine learning',list_name='demo'))
        def permit(op,attempt,ch=None,parent=None,**over):
            b=dict(scope=scope,op=op,attempt=attempt,parent=parent or par())
            if ch is not None:b['child']=ch
            b.update(over)
            return dict(body=b,signature=key.sign(DOMAIN+enc(b)).hex())
        def start(crash='none'):
            nonlocal process
            assert process is None
            sock.unlink(missing_ok=True);cfg.write_bytes(enc(dict(conf,crash=crash)));cfg.chmod(0o644)
            log=out/('broker-%02d.log'%len(broker_logs));f=log.open('wb')
            process=subprocess.Popen([sys.executable,str(code/'broker.py'),str(cfg)],stdout=f,stderr=subprocess.STDOUT,user=BROKER,group=BROKER,extra_groups=[],cwd=base)
            broker_logs.append((log,f))
            for _ in range(200):
                if process.poll() is not None:raise RuntimeError('broker start failed:'+log.read_text())
                if sock.exists():return
                time.sleep(.05)
            raise RuntimeError('broker start timeout')
        def stop(expected=None):
            nonlocal process
            if process is None:return
            if expected is None:
                process.terminate();rc=process.wait(timeout=10);assert rc in (-15,0),rc
            else:
                rc=process.wait(timeout=10);assert rc==expected,(rc,expected)
            broker_logs[-1][1].close();process=None
            return rc
        def worker(req,p=None,target=db):
            env=dict(os.environ,B58_UPSTREAM=str(up),B58_DB=str(target),B58_SOCKET=str(sock),B58_PERMIT=enc(p).decode(),PYTHONDONTWRITEBYTECODE='1')
            x=subprocess.run([sys.executable,str(code/'worker.py')],input=enc(req)+b'\n',capture_output=True,timeout=45,env=env,cwd=base,user=APP,group=APP,extra_groups=[])
            return dict(exit=x.returncode,result=parse(x.stdout.splitlines()[-1]) if x.stdout.splitlines() else {},stderr=x.stderr.decode(errors='replace'))
        def app(mode='guarded',tool='plan_reading',arguments=None):return dict(mode=mode,tool=tool,arguments=arguments or par()['arguments'])
        def direct(p,ch):return dict(mode='broker',permit=p,child=ch)
        def check(name,req,p=None,target=db,status=None,error=None,delta=0,receipt_delta=0,crash=None):
            before=read_db(target);r=worker(req,p,target)
            if crash is not None:stop(crash)
            after=read_db(target)
            event=dict(name=name,request=req,permit=p,worker=r,before=before,after=after)
            if crash is not None:event['broker_exit']=crash
            events.append(event);(out/'events.json').write_bytes(enc(events))
            assert r['exit']==0,(name,r)
            result=r['result'];rendered=json.dumps(result)
            if error is not None:assert not result.get('ok') and error in rendered,(name,r)
            else:
                assert result.get('ok'),(name,r)
                if status:assert status in rendered,(name,r)
            assert len(after['rows'])-len(before['rows'])==delta,(name,before,after)
            assert len(after['receipts'])-len(before['receipts'])==receipt_delta,(name,before,after)
            assert all(x in after['rows'] for x in before['rows']),name
            print('B58_CASE',name,'rows',len(after['rows']),'receipts',len(after['receipts']),flush=True)
            return result
        try:
            check('unguarded-original-plan',app('original'),target=baseline/'reading.sqlite3',status='created',delta=1)
            shutil.copyfile(baseline/'reading.sqlite3',out/'baseline.sqlite3')
            start()
            plan=permit('op-plan','attempt-plan',child('B004'))
            check('original-mcp-plan',app('mcp'),plan,status='created',delta=1,receipt_delta=1)
            check('different-child',app(),permit('wrong-child','wrong-child',child('B001')),error='CHILD_MISMATCH')
            check('parent-only',app(),permit('parent-only','parent-only'),error='MISSING_CHILD_PERMIT')
            check('wrong-scope',app(),permit('scope','scope',child('B004'),scope='elsewhere'),error='WRONG_SCOPE')
            bad=permit('bad','bad',child('B004'));bad['signature']=('00' if bad['signature'][:2]!='00' else '01')+bad['signature'][2:]
            check('tampered-signature',app(),bad,error='INVALID_SIGNATURE')
            check('original-method-bypass',app('original','save_reading_item',child('B006')),error='STORAGE_UNAVAILABLE')
            check('raw-db-write-bypass',dict(mode='raw'),error='unable to open database')
            check('raw-db-read-bypass',dict(mode='read'),error='unable to open database')
            check('missing-permit-direct',direct(None,child('B006')),error='MISSING_CHILD_PERMIT')
            stop();start()
            check('restart-replay',direct(plan,child('B004')),status='"replay": true')
            check('same-op-new-attempt',direct(permit('op-plan','attempt-retry',child('B004')),child('B004')),status='OTHER_ATTEMPT_WON',receipt_delta=1)
            ch=child('B001');p=par('save_reading_item',ch)
            check('operation-conflict',direct(permit('op-plan','attempt-conflict',ch,p),ch),error='OP_CONFLICT')
            check('attempt-conflict',direct(permit('other-op','attempt-plan',ch,p),ch),error='ATTEMPT_CONFLICT')
            check('distinct-op-existing-row',direct(permit('distinct','distinct-attempt',child('B004')),child('B004')),status='ALREADY_PRESENT',receipt_delta=1)
            before=read_db(db)
            ps=[permit('parallel','parallel-'+str(i),ch,p) for i in range(2)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:rs=list(pool.map(lambda t:worker(direct(t,ch)),ps))
            after=read_db(db);events.append(dict(name='parallel-same-op',permits=ps,workers=rs,before=before,after=after));(out/'events.json').write_bytes(enc(events))
            assert all(x['exit']==0 and x['result']['ok'] for x in rs)
            assert sorted(x['result']['receipt']['status'] for x in rs)==['EFFECT_ATTRIBUTED','OTHER_ATTEMPT_WON']
            assert len(after['rows'])==len(before['rows'])+1 and len(after['receipts'])==len(before['receipts'])+2
            print('B58_CASE parallel-same-op rows',len(after['rows']),'receipts',len(after['receipts']),flush=True)
            stop();start('before')
            ch2=child('B002');b2=permit('crash-before','before-attempt',ch2,par('save_reading_item',ch2))
            check('crash-before-commit',direct(b2,ch2),error='TRANSPORT_UNKNOWN',crash=81)
            start();check('recover-before-commit',direct(b2,ch2),status='EFFECT_ATTRIBUTED',delta=1,receipt_delta=1)
            stop();start('after')
            ch3=child('B003');b3=permit('crash-after','after-attempt',ch3,par('save_reading_item',ch3))
            check('crash-after-commit',direct(b3,ch3),error='TRANSPORT_UNKNOWN',delta=1,receipt_delta=1,crash=82)
            start();check('recover-after-commit',direct(b3,ch3),status='"replay": true')
            # This counterexample is a scope limit: exact child authority does not prove approved parent execution.
            ch5=child('B005');p5=permit('path-limit','path-limit',ch5,par('plan_reading',dict(query='agents',list_name='demo')))
            check('authorized-child-direct-path-limit',app('guarded','save_reading_item',ch5),p5,status='created',delta=1,receipt_delta=1)
            stop()
            final=read_db(db)
            assert [(x[0],x[1]) for x in final['rows']]==[('demo','B001'),('demo','B002'),('demo','B003'),('demo','B004'),('demo','B005')]
            assert len(final['receipts'])==8 and sum(x['status']=='EFFECT_ATTRIBUTED' for x in final['receipts'])==5
            with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as original,sqlite3.connect(out/'destination.sqlite3') as copy:
                assert original.execute('PRAGMA integrity_check').fetchone()==('ok',)
                original.backup(copy)
            for p,h in PINS.items():assert blob(up/p)==h,p
            (out/'summary.json').write_bytes(enc(dict(cases=len(events),final=final,app_uid=APP,broker_uid=BROKER,db_mode=oct(private.stat().st_mode&0o777),actual_mcp=True,scope_limit='authorized child via different path succeeds')))
            print('B58_PASS',len(events),'cases',len(final['rows']),'rows',len(final['receipts']),'receipts',flush=True)
        finally:stop()
if __name__=='__main__':main(*sys.argv[1:])
