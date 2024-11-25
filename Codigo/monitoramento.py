import sys
import socket
import struct
import datetime


def decodificar_dns(dados):
    try:
        nome_consulta = ""
        offset = 12  # Offset do cabeçalho DNS
        while True:
            tamanho = dados[offset]
            if tamanho == 0:
                break
            nome_consulta += dados[offset + 1:offset + 1 + tamanho].decode() + "."
            offset += tamanho + 1
            
        return nome_consulta[:-1]  # Remove o último "."
    except:
        return None

def decodificar_http(dados):
    try:
        dados_http = dados.decode("utf-8", errors="ignore")
        if "Host:" in dados_http:
            cabecalhos = dados_http.split("\r\n")
            for cabecalho in cabecalhos:
                if cabecalho.startswith("Host:"):
                    return cabecalho.split(":")[1].strip()
        return None
    except:
        return None


# Função para criar o arquivo HTML
def criar_arquivo_html(historico):
    with open("./assets/historico.html", "w") as arquivo:
        arquivo.write("<html>\n")
        arquivo.write("<head>\n")
        arquivo.write("<title>Histórico de Navegação</title>\n")
        arquivo.write("</head>\n")
        arquivo.write("<h1>Histórico:</h1>\n")
        arquivo.write("<body>\n")
        arquivo.write("<ul>\n")
        for entrada in historico:
            arquivo.write(f"<li>{entrada['data_hora']} - {entrada['ip']} - <a href={entrada['url']}>{entrada['url']}</a></li>\n")
        arquivo.write("</ul>\n")
        arquivo.write("</body>\n")
        arquivo.write("</html>\n")
    arquivo.close()

# Configuração do socket raw
def farejador(ip_maquina_vitima):
    historico = []
    socket_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # socket para receber pacotes

    print("Farejador rodando... Pressione Ctrl+C para parar.")
    try:
        while True:
            pacote, endereco = socket_raw.recvfrom(65535)
            
            # Cabeçalho Ethernet
            tamanho_ethernet = 14
            cabecalho_ethernet = pacote[:tamanho_ethernet]
            dados_ethernet = struct.unpack("!6s6sH", cabecalho_ethernet)
            protocolo_ethernet = dados_ethernet[2]

            # Verifica se é IPv4
            if protocolo_ethernet == 0x0800:
                cabecalho_ip = pacote[tamanho_ethernet:tamanho_ethernet + 20]
                dados_ip = struct.unpack("!BBHHHBBH4s4s", cabecalho_ip)

                # Obtém IP de origem
                ip_origem = socket.inet_ntoa(dados_ip[8])
                
                if ip_origem != ip_maquina_vitima:
                    continue

                # Verifica protocolo de transporte (TCP/UDP)
                protocolo = dados_ip[6]

                if protocolo == 6:  # TCP
                    cabecalho_tcp = pacote[tamanho_ethernet + 20:tamanho_ethernet + 40]
                    dados_tcp = struct.unpack("!HHLLBBHHH", cabecalho_tcp)

                    # Porta de destino
                    porta_destino = dados_tcp[1]

                    # Verifica se é HTTP
                    if porta_destino == 80:
                        dados_http = pacote[tamanho_ethernet + 40:]
                        url = decodificar_http(dados_http)
                        if url:
                            historico.append({
                                "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": ip_origem,
                                "url": f"http://{url}"
                            })
                            print(f"[HTTP] {ip_origem} -> http://{url}")

                elif protocolo == 17:  # UDP
                    cabecalho_udp = pacote[tamanho_ethernet + 20:tamanho_ethernet + 28]
                    dados_udp = struct.unpack("!HHHH", cabecalho_udp)

                    # Porta de destino
                    porta_destino = dados_udp[1]

                    # Verifica se é DNS
                    if porta_destino == 53:
                        dados_dns = pacote[tamanho_ethernet + 28:]
                        dominio = decodificar_dns(dados_dns)
                        if dominio:
                            historico.append({
                                "data_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ip": ip_origem,
                                "url": dominio
                            })
                            print(f"[DNS] {ip_origem} -> {dominio}")

    except KeyboardInterrupt:
        print("\nParando o farejador...")
        criar_arquivo_html(historico)

# Executa o farejador
if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Uso: sudo {} <ip da máquina vítima>".format(sys.argv[0]))
        sys.exit(0)

    farejador(sys.argv[1])
