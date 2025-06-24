import ipaddress
from iputils import *

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            next_hop = self._next_hop(dst_addr)
            if next_hop:
                # Nos Passos 4 e 5, o TTL será decrementado aqui.
                # Por enquanto, apenas encaminha.
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        try:
            ip_destino_obj = ipaddress.ip_address(dest_addr)
        except ValueError:
            return None

        # Graças à ordenação feita em definir_tabela_encaminhamento,
        # basta pegar o primeiro match.
        for cidr, next_hop in self.tabela:
            try:
                rede = ipaddress.ip_network(cidr, strict=False)
                if ip_destino_obj in rede:
                    return next_hop
            except ValueError:
                continue
        
        return None

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento. Para implementar a regra do
        prefixo mais longo, a tabela é ordenada pela máscara de rede,
        da mais específica (maior número) para a mais genérica (menor número).
        """
        # Usamos uma função lambda como chave de ordenação.
        # Ela extrai o número do prefixo do CIDR (o que vem depois do '/')
        # e o converte para inteiro para ordenar.
        # `reverse=True` faz a ordenação ser do maior para o menor.
        self.tabela = sorted(tabela, key=lambda item: int(item[0].split('/')[1]), reverse=True)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        # Será implementado no Passo 2.
        pass