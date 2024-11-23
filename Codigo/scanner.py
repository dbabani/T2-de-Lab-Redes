import socket
import struct
import sys
import time
import ipaddress

def checksum(data):
    """
    Calcula o checksum para o cabeçalho.
    """
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def create_icmp_packet():
    """
    Cria um pacote ICMP Echo Request.
    """
    icmp_header = struct.pack(
        '!BBHI',
        8,                 # Tipo (8 para Echo Request)
        0,                 # Código
        0,                 # Checksum (calculado depois)
        0x00000000         # Identificador
    )
    icmp_checksum = checksum(icmp_header)
    return struct.pack(
        '!BBHI',
        8,                 # Tipo
        0,                 # Código
        icmp_checksum,     # Checksum
        0x00000000         # Identificador
    )

def scan_network(network, timeout):
    """
    Realiza a varredura ICMP na rede especificada.
    """
    active_hosts = []
    network = ipaddress.ip_network(network, strict=False)
    hosts = list(network.hosts())
    total_hosts = len(hosts)
    print(f"Varredura iniciada para {total_hosts} hosts.")

    start_time = time.time()

    for host in hosts:
        host = str(host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout / 1000.0)
        except PermissionError:
            print("Permissão negada. Execute como root.")
            sys.exit(1)

        icmp_packet = create_icmp_packet()

        # Medir o tempo de envio e resposta
        try:
            send_time = time.time()
            sock.sendto(icmp_packet, (host, 0))

            # Receber resposta
            response, _ = sock.recvfrom(1024)
            recv_time = time.time()

            # Verificar se é um Echo Reply
            icmp_type, icmp_code = struct.unpack('!BB', response[20:22])
            if icmp_type == 0 and icmp_code == 0:
                response_time = (recv_time - send_time) * 1000
                active_hosts.append((host, response_time))
                print(f"Host ativo: {host}, Tempo de resposta: {response_time:.2f} ms")
        except socket.timeout:
            pass  # Sem resposta
        except OSError as e:
            print(f"Erro no envio para {host}: {e}")
        finally:
            sock.close()

    end_time = time.time()
    total_time = end_time - start_time

    print(f"\nVarredura concluída em {total_time:.2f} segundos.")
    print(f"Total de hosts na rede: {total_hosts}")
    print(f"Hosts ativos encontrados: {len(active_hosts)}")
    for host, response_time in active_hosts:
        print(f"- {host}: {response_time:.2f} ms")

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <rede/máscara> <tempo limite (ms)>")
        sys.exit(1)

    network = sys.argv[1]
    try:
        timeout = int(sys.argv[2])
        if timeout <= 0:
            raise ValueError("Tempo limite deve ser maior que zero.")
    except ValueError as e:
        print(f"Erro no tempo limite: {e}")
        sys.exit(1)

    scan_network(network, timeout)

if __name__ == "__main__":
    main()
