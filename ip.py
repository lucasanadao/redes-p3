from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        # ADICIONADO: Inicializa a tabela de encaminhamento como uma lista vazia.
        self.tabela_encaminhamento = []

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
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # LÓGICA DO PASSO 1 IMPLEMENTADA AQUI
        """
        Usa a tabela de encaminhamento para determinar o próximo salto
        (next_hop) a partir do endereço de destino (dest_addr).
        """
        try:
            # Converte o IP de destino para um objeto, facilitando a comparação
            ip_destino_obj = ipaddress.ip_address(dest_addr)
        except ValueError:
            # Endereço de destino inválido
            return None

        # Itera sobre a tabela de encaminhamento
        for cidr, next_hop in self.tabela_encaminhamento:
            try:
                # Cria um objeto de rede a partir do CIDR
                rede = ipaddress.ip_network(cidr, strict=False)

                # Verifica se o endereço de destino pertence a esta rede
                if ip_destino_obj in rede:
                    # No Passo 1, o primeiro resultado encontrado é o correto.
                    return next_hop
            except ValueError:
                # Ignora CIDRs inválidos na tabela, se houver
                continue

        # Se não encontrou nenhuma rota na tabela, retorna None
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        # LÓGICA DO PASSO 1 IMPLEMENTADA AQUI
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        """
        # Apenas armazena a tabela recebida no atributo da classe.
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        # datagrama = ... (Será feito no Passo 2)
        # self.enlace.enviar(datagrama, next_hop)
        pass # Deixamos o 'pass' por enquanto para não dar erro
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

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
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # LÓGICA DO PASSO 1 IMPLEMENTADA AQUI
        """
        Usa a tabela de encaminhamento para determinar o próximo salto
        (next_hop) a partir do endereço de destino (dest_addr).
        """
        try:
            # Converte o IP de destino para um objeto, facilitando a comparação
            ip_destino_obj = ipaddress.ip_address(dest_addr)
        except ValueError:
            # Endereço de destino inválido
            return None

        # Itera sobre a tabela de encaminhamento
        for cidr, next_hop in self.tabela_encaminhamento:
            try:
                # Cria um objeto de rede a partir do CIDR
                rede = ipaddress.ip_network(cidr, strict=False)

                # Verifica se o endereço de destino pertence a esta rede
                if ip_destino_obj in rede:
                    # No Passo 1, o primeiro resultado encontrado é o correto.
                    return next_hop
            except ValueError:
                # Ignora CIDRs inválidos na tabela, se houver
                continue

        # Se não encontrou nenhuma rota na tabela, retorna None
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        # LÓGICA DO PASSO 1 IMPLEMENTADA AQUI
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        """
        # Apenas armazena a tabela recebida no atributo da classe.
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)
