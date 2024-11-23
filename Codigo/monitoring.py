import socket
import struct
import datetime
from typing import Tuple

# Função para converter endereço IP
def ip_to_str(address: bytes) -> str:
    return '.'.join(map(str, address))

# Função para obter o nome do host a partir do IP
def get_host_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Desconhecido"

# Função para extrair o cabeçalho IP
def parse_ip_header(packet: bytes) -> Tuple[str, str, int]:
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    src_ip = ip_to_str(ip_header[8])
    dest_ip = ip_to_str(ip_header[9])
    protocol = ip_header[6]
    return src_ip, dest_ip, protocol

# Função para extrair o cabeçalho TCP
def parse_tcp_header(packet: bytes) -> Tuple[int, int]:
    tcp_header = struct.unpack('!HH', packet[:4])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    return src_port, dest_port

# Sniffer principal
def start_sniffer():
    # Cria o socket raw para pacotes IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Iniciando o sniffer... Pressione Ctrl+C para parar.")
    logs = []

    try:
        while True:
            # Recebe os pacotes
            raw_packet, addr = sniffer.recvfrom(65535)

            # Extraindo informações do cabeçalho IP
            ip_src, ip_dest, protocol = parse_ip_header(raw_packet[:20])

            # Obter o nome do host
            host_name = get_host_name(ip_src)

            # Verifica se é um pacote TCP (protocolo 6)
            if protocol == 6:
                src_port, dest_port = parse_tcp_header(raw_packet[20:24])

                # Caso seja HTTP (porta 80) ou HTTPS (porta 443)
                if dest_port == 80 or dest_port == 443:
                    timestamp = datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
                    url = raw_packet[54:].decode('utf-8', 'ignore')  # Aqui poderia ser extraído de um pacote HTTP
                    logs.append(
                        f"<li>{timestamp} - {ip_src} - {host_name} - <a href='{url}'>{url}</a></li>"
                    )
                    print(f"HTTP(s) - {ip_src}:{src_port} -> {ip_dest}:{dest_port}")

    except KeyboardInterrupt:
        print("\nEncerrando o sniffer.")
    finally:
        # Gerar o arquivo HTML com os logs
        with open("./assets/historico.html", "w") as f:
            f.write("<html><body><h1>Histórico de Navegação</h1><ul>")
            f.writelines(logs)
            f.write("</ul></body></html>")
        print("Arquivo 'history.html' gerado com sucesso!")

if __name__ == "__main__":
    start_sniffer()
