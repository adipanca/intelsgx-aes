#!/usr/bin/env python3
import socket, struct
SOCK="/tmp/aead-kms.sock"; KID=0
def call(op,aad,data):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(SOCK)
    s.sendall(struct.pack("!cIII",op.encode(),KID,len(aad),len(data))+aad+data)
    raw=s.recv(4); 
    if len(raw)!=4: raise RuntimeError("short read len")
    L,=struct.unpack("!I",raw)
    if L==0xFFFFFFFF: raise RuntimeError("agent ERROR")
    out=b""
    while len(out)<L:
        ch=s.recv(L-len(out))
        if not ch: raise RuntimeError("short read")
        out+=ch
    s.close(); return out

aad=b""; pt=b"hello sgx"
blob=call('E',aad,pt); print("ENC OK len=",len(blob))
pt2=call('D',aad,blob); print("DEC OK pt=",pt2); assert pt2==pt
