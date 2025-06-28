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
        # A leitura do cabeçalho continua igual
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            
            # 1. Verifica se o TTL vai expirar. Se sim, descarta.
            if ttl <= 1:
                return

            next_hop = self._next_hop(dst_addr)
            if next_hop is None:
                return

            # 2. Cria uma cópia MUTÁVEL do cabeçalho original para modificação
            novo_header_mutavel = bytearray(datagrama[:20])

            # 3. Decrementa o TTL. O TTL está no 9º byte (índice 8).
            novo_header_mutavel[8] = ttl - 1

            # 4. Zera o campo de checksum (11º e 12º bytes, índices 10 e 11)
            novo_header_mutavel[10] = 0
            novo_header_mutavel[11] = 0

            # 5. Calcula o novo checksum sobre o cabeçalho modificado
            novo_checksum = calc_checksum(novo_header_mutavel)

            # 6. Insere o novo checksum de volta no cabeçalho.
            # Usamos struct.pack para garantir a ordem correta dos bytes (big-endian)
            struct.pack_into('!H', novo_header_mutavel, 10, novo_checksum)
            
            # 7. Monta o novo datagrama com o cabeçalho finalizado e o payload original
            novo_datagrama = bytes(novo_header_mutavel) + payload

            # 8. Envia o novo datagrama, que agora está correto
            self.enlace.enviar(novo_datagrama, next_hop)        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
                src_addr, dst_addr, payload = read_ipv4_header(datagrama)
            
            if dst_addr == self.meu_endereco:
                # atua como host
                if proto == IPPROTO_TCP and self.callback:
                    self.callback(src_addr, dst_addr, payload)
            else:
                # atua como roteador
                
                # Passo 4.1: Se o TTL for 1 ou menos, o datagrama expira aqui.
                # Ele deve ser descartado.
                if ttl <= 1:
                    # No Passo 5, enviaremos uma mensagem ICMP de volta antes de descartar.
                    # Por enquanto, apenas retornamos, efetivamente descartando o pacote.
                    return

                # Encontra o próximo salto
                next_hop = self._next_hop(dst_addr)

                # Se não houver rota, descarte o pacote
                if next_hop is None:
                    return

                # Passo 4.2: Decrementa o TTL
                novo_ttl = ttl - 1

                # Passo 4.3: Recalcula o checksum.
                # Para isso, precisamos remontar o cabeçalho com o novo TTL.
                # A lógica é a mesma do seu método enviar().
                
                # Recria os campos compostos do cabeçalho original
                ver_ihl = (4 << 4) + 5 # Versão 4, IHL 5
                flags_frag = (flags << 13) | frag_offset
                
                # Converte endereços de string para bytes
                src_bytes = str2addr(src_addr)
                dst_bytes = str2addr(dst_addr)
                
                # Monta o cabeçalho temporário com checksum 0 para o cálculo
                header_sem_checksum = struct.pack(
                    '!BBHHHBBH4s4s',
                    ver_ihl,
                    (dscp << 2) | ecn,
                    len(datagrama), # O tamanho total do datagrama não muda
                    identification,
                    flags_frag,
                    novo_ttl,      # USA O NOVO TTL
                    proto,
                    0,             # Checksum zerado para cálculo
                    src_bytes,
                    dst_bytes
                )

                # Calcula o novo checksum
                novo_checksum = calc_checksum(header_sem_checksum)

                # Monta o cabeçalho final com o checksum correto
                novo_header = struct.pack(
                    '!BBHHHBBH4s4s',
                    ver_ihl,
                    (dscp << 2) | ecn,
                    len(datagrama),
                    identification,
                    flags_frag,
                    novo_ttl,      # USA O NOVO TTL
                    proto,
                    novo_checksum, # USA O NOVO CHECKSUM
                    src_bytes,
                    dst_bytes
                )

                # Monta o novo datagrama completo
                novo_datagrama = novo_header + payload

                # Envia o NOVO datagrama para o próximo salto
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