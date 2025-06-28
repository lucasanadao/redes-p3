from iputils import *
import ipaddress


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

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            
            if ttl <= 1:
                return

            next_hop = self._next_hop(dst_addr)
            if next_hop is None:
                return

            # Cria uma cópia MUTÁVEL do cabeçalho
            novo_header_mutavel = bytearray(datagrama[:20])

            # Decrementa o TTL (byte de índice 8)
            novo_header_mutavel[8] = ttl - 1

            # Zera o campo de checksum (bytes de índice 10 e 11)
            novo_header_mutavel[10] = 0
            novo_header_mutavel[11] = 0

            # !! A CORREÇÃO ESTÁ AQUI !!
            # Converte o bytearray de volta para bytes antes de calcular o checksum,
            # para garantir que o tipo do dado seja o esperado pela função.
            novo_checksum = calc_checksum(bytes(novo_header_mutavel))

            # Insere o novo checksum de volta no cabeçalho mutável
            struct.pack_into('!H', novo_header_mutavel, 10, novo_checksum)
            
            # Monta o novo datagrama e o envia
            novo_datagrama = bytes(novo_header_mutavel) + payload
            self.enlace.enviar(novo_datagrama, next_hop)
        
    def _next_hop(self, dest_addr):
        """
        Para o dest_addr dado, retorna o next_hop correspondente na tabela,
        escolhendo a rede com maior prefixo que contém o endereço.
        """
        ip = ipaddress.IPv4Address(dest_addr)
        melhor_entrada = None
        maior_prefixo = -1

        for rede, next_hop in self._tabela_encaminhamento:
            if ip in rede and rede.prefixlen > maior_prefixo:
                melhor_entrada = next_hop
                maior_prefixo = rede.prefixlen

        return melhor_entrada


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Recebe uma lista de tuplas (cidr, next_hop)
        Armazena a tabela convertendo os CIDRs para objetos IPv4Network.
        """
        self._tabela_encaminhamento = []
        for cidr, next_hop in tabela:
            rede = ipaddress.IPv4Network(cidr, strict=False)
            self._tabela_encaminhamento.append((rede, next_hop))


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback


    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, montando o cabeçalho IP manualmente.
        """
        next_hop = self._next_hop(dest_addr)

        version = 4
        ihl = 5  # cabeçalho IP padrão tem 20 bytes
        ver_ihl = (version << 4) + ihl
        dscp = 0
        ecn = 0
        total_length = 20 + len(segmento)
        identification = 0
        flags = 0
        frag_offset = 0
        flags_frag = (flags << 13) | frag_offset
        ttl = 64
        protocolo = IPPROTO_TCP  # assumido como padrão
        checksum = 0  # temporariamente zero

        src = str2addr(self.meu_endereco)
        dst = str2addr(dest_addr)

        # Monta cabeçalho IP com checksum = 0 para cálculo
        header_sem_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl,
            (dscp << 2) | ecn,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocolo,
            checksum,
            src,
            dst
        )

        # Calcula o checksum e remonta o cabeçalho com o valor correto
        checksum = calc_checksum(header_sem_checksum)
        header = struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl,
            (dscp << 2) | ecn,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocolo,
            checksum,
            src,
            dst
        )

        datagrama = header + segmento
        self.enlace.enviar(datagrama, next_hop)