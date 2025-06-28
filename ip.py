# ip.py - VERSÃO FINAL UNIFICADA

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
        """
        Define e processa a tabela de encaminhamento. A tabela é ordenada
        pelo tamanho do prefixo para tornar a busca de rotas (longest prefix match)
        mais eficiente.
        """
        # A chave de ordenação extrai o número do prefixo (ex: de '192.168.0.0/24' pega o 24)
        # `reverse=True` ordena do maior prefixo para o menor (mais específico para o mais genérico)
        try:
            tabela_ordenada = sorted(tabela, key=lambda item: int(item[0].split('/')[1]), reverse=True)
        except (ValueError, IndexError):
            # Lida com possíveis CIDRs malformados na tabela de teste
            tabela_ordenada = tabela

        self.tabela_encaminhamento = []
        for cidr, next_hop in tabela_ordenada:
            try:
                self.tabela_encaminhamento.append((ipaddress.ip_network(cidr, strict=False), next_hop))
            except ValueError:
                continue

    def _next_hop(self, dest_addr):
        """
        Retorna o próximo salto para um determinado endereço de destino.
        """
        try:
            ip_destino = ipaddress.ip_address(dest_addr)
        except ValueError:
            return None

        # Graças à tabela pré-ordenada, o primeiro "match" encontrado já é o correto
        # (o que tem o prefixo mais longo).
        for rede, next_hop in self.tabela_encaminhamento:
            if ip_destino in rede:
                return next_hop
        return None

    def __raw_recv(self, datagrama):
        """
        Recebe um datagrama e o processa, atuando como host ou roteador.
        """
        try:
            header_len = (datagrama[0] & 0x0F) * 4
            _, _, _, _, _, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        except Exception:
            return # Descarta pacotes malformados

        if dst_addr == self.meu_endereco:
            # Lógica de Host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Lógica de Roteador
            if ttl <= 1:
                # Passo 5: Enviar ICMP Time Exceeded aqui
                return

            next_hop = self._next_hop(dst_addr)
            if next_hop is None:
                return # Sem rota, descarta

            # Modificação do cabeçalho
            novo_header_mutavel = bytearray(datagrama[:header_len])
            novo_header_mutavel[8] = ttl - 1
            novo_header_mutavel[10:12] = b'\x00\x00' # Zera o checksum
            
            novo_checksum = calc_checksum(bytes(novo_header_mutavel))
            struct.pack_into('!H', novo_header_mutavel, 10, novo_checksum)
            
            novo_datagrama = bytes(novo_header_mutavel) + payload
            self.enlace.enviar(novo_datagrama, next_hop)

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia um segmento para um destino (usado pelo Teste 2).
        Esta é a sua implementação original que já funcionava.
        """
        next_hop = self._next_hop(dest_addr)
        if not next_hop:
            return
        
        ver_ihl = (4 << 4) + 5
        total_length = 20 + len(segmento)
        flags_frag = 0
        ttl = 64
        protocolo = IPPROTO_TCP
        checksum = 0

        src = str2addr(self.meu_endereco)
        dst = str2addr(dest_addr)

        header_sem_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, 0, total_length, 0, flags_frag, ttl, protocolo, checksum, src, dst
        )
        checksum_calculado = calc_checksum(header_sem_checksum)
        header_com_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl, 0, total_length, 0, flags_frag, ttl, protocolo, checksum_calculado, src, dst
        )

        datagrama = header_com_checksum + segmento
        self.enlace.enviar(datagrama, next_hop)