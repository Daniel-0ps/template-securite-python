from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from scapy.all import sniff, IP, ARP, TCP, UDP, ICMP
from collections import defaultdict
import time


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocols_count = defaultdict(int)
        self.attacks = []
        self.ips_info = defaultdict(lambda: {"packets": 0, "protocols": set()})

    def capture_traffic(self, packet_count: int = 50, timeout: int = 30) -> None:
        """
        Capture network trafic from an interface
        :param packet_count: Nombre de paquets à capturer
        :param timeout: Délai d'expiration en secondes
        """
        interface = self.interface
        if not interface:
            logger.error("Aucune interface sélectionnée")
            return

        logger.info(f"Capture traffic from interface {interface} ({packet_count} paquets)")

        try:
            sniff(
                iface=interface,
                prn=self._packet_callback,
                store=False,
                count=packet_count,
                timeout=timeout
            )
            logger.info(f"Capture terminée : {len(self.packets)} paquets reçus")
        except PermissionError:
            logger.error("Erreur : Vous devez avoir les droits administrateur pour capturer le trafic")
        except Exception as e:
            logger.error(f"Erreur lors de la capture : {e}")

    def _packet_callback(self, packet) -> None:
        """
        Callback pour traiter chaque paquet capturé
        """
        self.packets.append(packet)
        self._extract_protocols(packet)
        self._detect_attacks(packet)

    def _extract_protocols(self, packet) -> None:
        """
        Extraire les protocoles du paquet
        """
        if IP in packet:
            self.protocols_count["IP"] += 1
            src_ip = packet[IP].src
            self.ips_info[src_ip]["packets"] += 1

            if TCP in packet:
                self.protocols_count["TCP"] += 1
                self.ips_info[src_ip]["protocols"].add("TCP")
            if UDP in packet:
                self.protocols_count["UDP"] += 1
                self.ips_info[src_ip]["protocols"].add("UDP")
            if ICMP in packet:
                self.protocols_count["ICMP"] += 1
                self.ips_info[src_ip]["protocols"].add("ICMP")

        if ARP in packet:
            self.protocols_count["ARP"] += 1

    def _detect_attacks(self, packet) -> None:
        """
        Détecter les attaques potentielles
        """
        attack_info = None

        # Détection ARP Spoofing
        if ARP in packet:
            if packet[ARP].op == 2:  # ARP Reply
                src_ip = packet[ARP].psrc
                src_mac = packet[ARP].hwsrc
                if src_ip in self.ips_info and len(self.ips_info[src_ip]) > 0:
                    attack_info = {
                        "type": "ARP Spoofing",
                        "src_ip": src_ip,
                        "src_mac": src_mac,
                        "timestamp": time.time()
                    }

        # Détection Port Scan (multiples ports différents)
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Simple heuristique : si SYN flag et ports variés
            if packet[TCP].flags & 0x02:  # SYN flag
                attack_info = {
                    "type": "Port Scan potentiel",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "timestamp": time.time()
                }

        if attack_info:
            self.attacks.append(attack_info)
            logger.warning(f"Attaque détectée : {attack_info['type']} depuis {attack_info.get('src_ip', 'Unknown')}")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        sorted_protocols = dict(sorted(self.protocols_count.items(), key=lambda x: x[1], reverse=True))
        logger.debug(f"Protocoles triés : {sorted_protocols}")
        return sorted_protocols

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        return dict(self.protocols_count)

    def analyse(self, protocols: str = None) -> None:
        """
        Analyse all captured data and return statement
        :param protocols: Protocole spécifique à analyser (optionnel)
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        if self.attacks:
            logger.warning(f"{len(self.attacks)} attaque(s) détectée(s)")
            for attack in self.attacks:
                logger.warning(f"  - {attack['type']} depuis {attack.get('src_ip', 'Unknown')}")
        else:
            logger.info("Aucune attaque détectée - Tout va bien ✓")

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = "=== RÉSUMÉ DE CAPTURE ===\n\n"
        summary += f"Total de paquets capturés : {len(self.packets)}\n"
        summary += f"Total d'attaques détectées : {len(self.attacks)}\n\n"

        summary += "Protocoles capturés :\n"
        sorted_protocols = self.sort_network_protocols()
        for proto, count in sorted_protocols.items():
            summary += f"  - {proto} : {count} paquets\n"

        if self.attacks:
            summary += "\nAttaques détectées :\n"
            for attack in self.attacks:
                summary += f"  - {attack['type']} depuis {attack.get('src_ip', 'Unknown')}\n"
        else:
            summary += "\nAucune attaque détectée - Tout va bien ✓\n"

        return summary
