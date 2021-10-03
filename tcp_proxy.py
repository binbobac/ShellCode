from socket import *
from sys import *
MainSocket = socket(AF_INET, SOCK_STREAM)
RemoteSocket = socket(AF_INET, SOCK_STREAM)
def Usage():
    print '[usage] TcpProxy.py [LocalPort] [TargetHost] [TargetPort]'

try:
    LPort = int(argv[1])
    THost = argv[2]
    TPort = int(argv[3])
except:
    Usage()
    exit(0)
def SetSocket():
    MainSocket.bind(('', LPort))
    MainSocket.listen(1)

def ForwardData(Data):
    RemoteSocket.connect((THost, TPort))
    RemoteSocket.send(Data)
    Rdata = RemoteSocket.recv(1024)
    RemoteSocket.close()
    return Rdata

def MainHandle():
    MainSock, MainAddr = MainSocket.accept()
    print 'Connected by ',MainAddr
    while True:
        Ldata = MainSock.recv(1024)
        Rdata = ForwardData(Ldata)
        MainSock.send(Rdata)


if __name__ == '__main__':
    SetSocket()
    MainHandle()
