#!/usr/bin/env python3
# Layered-decode brute-forcer: tries all op-chains (depth<=N) over every /code
# file AND every TARGET HTTP path / TCP banner, auto-submits a valid flag.
# 0 model calls. Inspired by vlad's defcamp-agent decode-chain idea, expanded.
import sys, re, os, base64, codecs, zlib, gzip, itertools, socket, urllib.request, io
FLAG = re.compile(rb'flag\{[0-9a-fA-F]{32}\}')
def _ok(b):
    try: t=b.decode('latin1')
    except Exception: return None
    m=FLAG.search(t.encode('latin1','ignore'))
    if not m: 
        m2=re.search(r'flag\{[0-9a-fA-F]{32}\}', t)
        return m2.group(0) if m2 else None
    f=m.group(0).decode()
    return None if re.match(r'flag\{(.)\1{31}\}$', f) else f

def _clean(b): return re.sub(rb'\s', b'', b)
def op_hex(b):
    s=_clean(b)
    if not re.fullmatch(rb'(?:[0-9a-fA-F]{2})+', s): raise ValueError
    return bytes.fromhex(s.decode())
def op_b64(b):
    s=_clean(b)
    if not re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}', s): raise ValueError
    return base64.b64decode(s+b'='*(-len(s)%4))
def op_b64url(b):
    s=_clean(b)
    if not re.fullmatch(rb'[A-Za-z0-9_\-]+={0,2}', s): raise ValueError
    return base64.urlsafe_b64decode(s+b'='*(-len(s)%4))
def op_b32(b):
    s=_clean(b).upper()
    if not re.fullmatch(rb'[A-Z2-7]+={0,6}', s): raise ValueError
    return base64.b32decode(s+b'='*(-len(s)%8))
def op_b85(b): return base64.b85decode(_clean(b))
def op_a85(b): return base64.a85decode(_clean(b))
def op_rev(b): return b[::-1]
def op_rot13(b): return codecs.encode(b.decode('latin1'),'rot13').encode('latin1')
def op_zlib(b): return zlib.decompress(b)
def op_gzip(b): return gzip.GzipFile(fileobj=io.BytesIO(b)).read()
def op_bin(b):
    s=_clean(b)
    if not re.fullmatch(rb'[01]+', s) or len(s)%8: raise ValueError
    return bytes(int(s[i:i+8],2) for i in range(0,len(s),8))
def op_dec(b):
    parts=re.split(rb'[,\s]+', b.strip())
    if not all(re.fullmatch(rb'\d{1,3}',p) for p in parts if p): raise ValueError
    return bytes(int(p) for p in parts if p)
def op_atbash(b):
    return bytes((219-c if 65<=c<=90 else 219-c if 97<=c<=122 else c) for c in b)
def op_rotall(b):  # try all caesar shifts folded: pick via validity downstream (1..25) -> handled separately
    raise ValueError
OPS={'hex':op_hex,'b64':op_b64,'b64url':op_b64url,'b32':op_b32,'b85':op_b85,'a85':op_a85,
     'rev':op_rev,'rot13':op_rot13,'zlib':op_zlib,'gzip':op_gzip,'bin':op_bin,'dec':op_dec,'atbash':op_atbash}
ORDER=list(OPS)

def search(data, depth=3):
    # BFS over chains; also try caesar 1..25 at each leaf
    seen=set(); frontier=[(data,[])]; 
    hit=_ok(data)
    if hit: return hit,[]
    for d in range(depth):
        nxt=[]
        for buf,chain in frontier:
            for name in ORDER:
                try: out=OPS[name](buf)
                except Exception: continue
                if not out or len(out)>200000: continue
                key=(name,bytes(out[:64]),len(out))
                if key in seen: continue
                seen.add(key)
                hit=_ok(out)
                if hit: return hit, chain+[name]
                # caesar sweep on this node
                for sh in range(1,26):
                    cz=bytes((97+(c-97+sh)%26 if 97<=c<=122 else 65+(c-65+sh)%26 if 65<=c<=90 else c) for c in out)
                    hc=_ok(cz)
                    if hc: return hc, chain+[name,f'caesar{sh}']
                nxt.append((out,chain+[name]))
        frontier=nxt
        if not frontier: break
    return None,None

def gather_targets():
    out=[]
    tg=os.environ.get('TARGETS','')
    for t in [x.strip() for x in tg.split(',') if x.strip()]:
        host,_,port=t.rpartition(':')
        # HTTP common paths
        for path in ('/','/flag.txt','/brace.txt','/flag','/index.html','/robots.txt','/.flag'):
            try:
                r=urllib.request.urlopen(f'http://{t}{path}',timeout=4); out.append(r.read(200000))
            except Exception: pass
        # raw TCP banner
        try:
            s=socket.create_connection((host,int(port)),timeout=4); s.settimeout(4)
            out.append(s.recv(65536)); s.close()
        except Exception: pass
    return out

if __name__=='__main__':
    root=sys.argv[1] if len(sys.argv)>1 else '/code'
    blobs=[]
    for dp,_,fs in os.walk(root):
        for fn in fs:
            p=os.path.join(dp,fn)
            try:
                if os.path.getsize(p)<=200000: blobs.append(open(p,'rb').read())
            except Exception: pass
    blobs += gather_targets()
    for b in blobs:
        f,chain=search(b, depth=int(os.environ.get('LAYERS_DEPTH','3')))
        if f: print('FLAG='+f); print('CHAIN='+'>'.join(chain), file=sys.stderr); sys.exit(0)
    print('NO_SOLUTION', file=sys.stderr); sys.exit(2)
