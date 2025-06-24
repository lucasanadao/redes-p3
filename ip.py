import ipaddress
from iputils import *

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede.
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        # Inicializa a tabela de encaminhamento.
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            if next_hop: # Apenas encaminha se houver uma rota
                # TODO: Trate corretamente o campo TTL do datagrama (Passos 4 e 5)
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        """
        Usa a tabela de encaminhamento para determinar o próximo salto.
        """
        try:
            ip_destino_obj = ipaddress.ip_address(dest_addr)
        except ValueError:
            return None # Endereço de destino com formato inválido

        # Itera sobre a tabela de encaminhamento
        for entrada in self.tabela:
            # Garante que a entrada da tabela tem o formato esperado
            if not isinstance(entrada, (list, tuple)) or len(entrada) != 2:
                continue
            
            cidr, next_hop = entrada
            
            try:
                rede = ipaddress.ip_network(cidr, strict=False)
                if ip_destino_obj in rede:
                    # Encontrou a rota, retorna o próximo salto
                    return next_hop
            except ValueError:
                # Ignora CIDRs com formato inválido na tabela
                continue
        
        # Nenhuma rota encontrada
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define o endereço IPv4 deste host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento.
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede.
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia um segmento para um endereço de destino.
        (Será implementado no Passo 2)
        """
        next_hop = self._next_hop(dest_addr)
        
        # A lógica para montar o datagrama virá no Passo 2
        # Por enquanto, não fazemos nada para não dar erro.
        pass