import socket, sys, threading
def tcp(p):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',p)); s.listen(50)
    while True:
        c,_=s.accept(); c.close()
def udp(p):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',p))
    while True:
        d,a=s.recvfrom(2048); s.sendto(b'\x00\x00\x81\x80'+d[4:12] if len(d)>=12 else b'ok',a)
for a in sys.argv[1:]:
    k,p=a.split(':'); threading.Thread(target=tcp if k=='t' else udp,args=(int(p),),daemon=True).start()
threading.Event().wait()
