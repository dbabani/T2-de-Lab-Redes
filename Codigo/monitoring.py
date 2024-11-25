#!/usr/bin/python3

import sys
import socket
import struct
import datetime


def decode_dns(data):
    try:
        query_name = ""
        offset = 12  # DNS header offfset
        while True:
            length = data[offset]
            if length == 0:
                break
            query_name += data[offset + 1:offset + 1 + length].decode() + "."
            offset += length + 1
            
        return query_name[:-1]  # Retira o último "."
    except:
        return None

def decode_http(data):
    try:
        http_data = data.decode("utf-8", errors="ignore")
        #print(http_data)
        if "Host:" in http_data:
            headers = http_data.split("\r\n")
            for header in headers:
                if header.startswith("Host:"):
                    return header.split(":")[1].strip()
        return None
    except:
        return None


# Função para criar o arquivo HTML
def criar_arquivo_html(historico):
    with open("./assets/historico.html", "w") as f:
        f.write("<html>\n")
        f.write("<head>\n")
        f.write("<title>Histórico de Navegação</title>\n")
        f.write("</head>\n")
        f.write("<h1>Histórico:</h1>\n")
        f.write("<body>\n")
        f.write("<ul>\n")
        for entrada in historico:
            f.write(f"<li>{entrada['data_hora']} - {entrada['ip']} - <a href={entrada['url']}>{entrada['url']}</a></li>\n")
        f.write("</ul>\n")
        f.write("</body>\n")
        f.write("</html>\n")
    f.close()

# Configuração do socket raw
def sniffer(ip_maquina_vitima):
    historico = []
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # socket para receber pacotes

    print("Sniffer rodando... Pressione Ctrl+C para parar.")
    try:
        while True:
            packet, addr = raw_socket.recvfrom(65535)
            
            # Ethernet Header
            eth_length = 14
            eth_header = packet[:eth_length]
            eth_data = struct.unpack("!6s6sH", eth_header)
            eth_protocol = eth_data[2]

            # Verifica se é IPv4
            if eth_protocol == 0x0800:
                ip_header = packet[eth_length:eth_length + 20]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

                # Obtem IP de origem
                src_ip = socket.inet_ntoa(iph[8])
                
                if (src_ip != ip_maquina_vitima):
                    continue

                # Verifica protocolo de transporte (TCP/UDP)
                protocol = iph[6]

                if protocol == 6:  # TCP
                    tcp_header = packet[eth_length + 20:eth_length + 40]
                    tcph = struct.unpack("!HHLLBBHHH", tcp_header)

                    # Porta de destino
                    dest_port = tcph[1]

                    # Verifica se é HTTP
                    if dest_port == 80:
                        http_data = packet[eth_length + 40:]
                        url = decode_http(http_data)
                        if url:
                            historico.append({
                                "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": src_ip,
                                "url": f"http://{url}"
                            })
                            print(f"[HTTP] {src_ip} -> http://{url}")

                elif protocol == 17:  # UDP
                    udp_header = packet[eth_length + 20:eth_length + 28]
                    udph = struct.unpack("!HHHH", udp_header)

                    # Porta de destino
                    dest_port = udph[1]

                    # Verifica se é DNS
                    if dest_port == 53:
                        #print("DNS")
                        dns_data = packet[eth_length + 28:]
                        domain = decode_dns(dns_data)
                        if domain:
                            historico.append({
                                "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": src_ip,
                                "url": domain
                            })
                            print(f"[DNS] {src_ip} -> {domain}")

    except KeyboardInterrupt:
        print("\nParando o sniffer...")
        criar_arquivo_html(historico)

# Executa o sniffer
if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Uso: sudo {} <ip da maquina vitima>".format(sys.argv[0]))
        sys.exit(0)

    sniffer(sys.argv[1])
