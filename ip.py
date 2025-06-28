import ipaddress
import struct
from iputils import *

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def definir_tabela_encaminhamento(self, tabela):
        try:
            tabela_ordenada = sorted(tabela, key=lambda item: int(item[0].split('/')[1]), reverse=True)
        except (ValueError, IndexError):
            tabela_ordenada = tabela

        self.tabela_encaminhamento = []
        for cidr, next_hop in tabela_ordenada:
            try:
                self.tabela_encaminhamento.append((ipaddress.ip_network(cidr, strict=False), next_hop))
            except ValueError:
                continue

    def _next_hop(self, dest_addr):
        try:
            ip_destino = ipaddress.ip_address(dest_addr)
        except ValueError:
            return None
        for rede, next_hop in self.tabela_encaminhamento:
            if ip_destino in rede:
                return next_hop
        return None

    def __raw_recv(self, datagrama):
        try:
            header_len = (datagrama[0] & 0x0F) * 4
            _, _, _, _, _, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        except Exception:
            return

        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else: # Roteador
            if ttl <= 1:
                # PASSO 5: TTL expirou. Enviar ICMP Time Exceeded.
                
                # 1. Monta o payload do ICMP: cabeçalho IP original + 8 primeiros bytes do payload original.
                icmp_payload = datagrama[:header_len + 8]

                # 2. Monta o cabeçalho ICMP (Tipo 11, Código 0) com checksum zerado
                #    Os 4 bytes não utilizados devem ser 0.
                icmp_header_sem_checksum = struct.pack('!BBHI', 11, 0, 0, 0)
                
                # Monta o pacote ICMP completo para calcular o checksum
                pacote_icmp_sem_checksum = icmp_header_sem_checksum + icmp_payload
                icmp_checksum = calc_checksum(pacote_icmp_sem_checksum)

                # Monta o cabeçalho ICMP final com o checksum correto
                icmp_header_com_checksum = struct.pack('!BBHI', 11, 0, icmp_checksum, 0)

                # Pacote ICMP final
                pacote_icmp = icmp_header_com_checksum + icmp_payload

                # 3. Envia o pacote ICMP de volta para a origem do pacote expirado.
                #    Nós usamos o método `enviar` para fazer isso, pois ele já sabe
                #    como montar um cabeçalho IP. Precisamos garantir que ele use
                #    o protocolo ICMP.
                self.enviar(pacote_icmp, src_addr, protocolo=IPPROTO_ICMP)

                # 4. Descarta o pacote original
                return

            next_hop = self._next_hop(dst_addr)
            if next_hop is None:
                return

            # Lógica do Passo 4 continua aqui...
            novo_header_mutavel = bytearray(datagrama[:header_len])
            novo_header_mutavel[8] = ttl - 1
            novo_header_mutavel[10:12] = b'\x00\x00'
            novo_checksum = calc_checksum(bytes(novo_header_mutavel))
            struct.pack_into('!H', novo_header_mutavel, 10, novo_checksum)
            novo_datagrama = bytes(novo_header_mutavel) + payload
            self.enlace.enviar(novo_datagrama, next_hop)

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocolo=IPPROTO_TCP):
        """
        Envia um segmento para um destino. Modificado para aceitar
        um protocolo customizado (útil para o ICMP).
        """
        next_hop = self._next_hop(dest_addr)
        if not next_hop:
            return
        
        ver_ihl = (4 << 4) + 5
        total_length = 20 + len(segmento)
        
        # Usamos o protocolo que foi passado como argumento
        header_sem_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, 0, total_length, 0, 0, 64, protocolo, 0, str2addr(self.meu_endereco), str2addr(dest_addr)
        )
        checksum_calculado = calc_checksum(header_sem_checksum)
        header_com_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, 0, total_length, 0, 0, 64, protocolo, checksum_calculado, str2addr(self.meu_endereco), str2addr(dest_addr)
        )

        datagrama = header_com_checksum + segmento
        self.enlace.enviar(datagrama, next_hop)