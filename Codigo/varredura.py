import socket
import struct
import sys
import time
import ipaddress

def calcular_checksum(dados):
    """
    Calcula o checksum para o cabeçalho.
    """
    soma = 0
    for i in range(0, len(dados), 2):
        palavra = (dados[i] << 8) + (dados[i + 1] if i + 1 < len(dados) else 0)
        soma += palavra
    soma = (soma >> 16) + (soma & 0xFFFF)
    soma += soma >> 16
    return ~soma & 0xFFFF

def criar_pacote_icmp():
    """
    Cria um pacote ICMP Echo Request.
    """
    cabecalho_icmp = struct.pack(
        '!BBHI',
        8,                 # Tipo (8 para Echo Request)
        0,                 # Código
        0,                 # Checksum (calculado depois)
        0x00000000         # Identificador
    )
    checksum_icmp = calcular_checksum(cabecalho_icmp)
    return struct.pack(
        '!BBHI',
        8,                 # Tipo
        0,                 # Código
        checksum_icmp,     # Checksum
        0x00000000         # Identificador
    )

def varrer_rede(rede, tempo_limite):
    """
    Realiza a varredura ICMP na rede especificada.
    """
    hosts_ativos = []
    rede = ipaddress.ip_network(rede, strict=False)
    hosts = list(rede.hosts())
    total_hosts = len(hosts)
    print(f"Varredura iniciada para {total_hosts} hosts.")

    tempo_inicio = time.time()

    for host in hosts:
        host = str(host)
        try:
            socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            socket_raw.settimeout(tempo_limite / 1000.0)
        except PermissionError:
            print("Permissão negada. Execute como root.")
            sys.exit(1)

        pacote_icmp = criar_pacote_icmp()

        # Medir o tempo de envio e resposta
        try:
            tempo_envio = time.time()
            socket_raw.sendto(pacote_icmp, (host, 0))

            # Receber resposta
            resposta, _ = socket_raw.recvfrom(1024)
            tempo_resposta = time.time()

            # Verificar se é um Echo Reply
            tipo_icmp, codigo_icmp = struct.unpack('!BB', resposta[20:22])
            if tipo_icmp == 0 and codigo_icmp == 0:
                tempo_resposta_ms = (tempo_resposta - tempo_envio) * 1000
                hosts_ativos.append((host, tempo_resposta_ms))
                print(f"Host ativo: {host}, Tempo de resposta: {tempo_resposta_ms:.2f} ms")
        except socket.timeout:
            pass  # Sem resposta
        except OSError as erro:
            print(f"Erro no envio para {host}: {erro}")
        finally:
            socket_raw.close()

    tempo_fim = time.time()
    tempo_total = tempo_fim - tempo_inicio

    print(f"\nVarredura concluída em {tempo_total:.2f} segundos.")
    print(f"Total de hosts na rede: {total_hosts}")
    print(f"Hosts ativos encontrados: {len(hosts_ativos)}")
    for host, tempo_resposta in hosts_ativos:
        print(f"- {host}: {tempo_resposta:.2f} ms")

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <rede/máscara> <tempo limite (ms)>")
        sys.exit(1)

    rede = sys.argv[1]
    try:
        tempo_limite = int(sys.argv[2])
        if tempo_limite <= 0:
            raise ValueError("O tempo limite deve ser maior que zero.")
    except ValueError as erro:
        print(f"Erro no tempo limite: {erro}")
        sys.exit(1)

    varrer_rede(rede, tempo_limite)

if __name__ == "__main__":
    main()
