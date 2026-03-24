"""Module Report

Contient la classe Report utilisée pour concaténer les résultats de capture
et sauvegarder un rapport au format TXT dans le dossier configuré.
"""

from datetime import datetime
from src.tp1.utils.config import logger
from src import config as project_config
import pygal
import os
import shutil
from pathlib import Path


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT IDS/IPS - ANALYSE DE TRAFIC RÉSEAU"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self.pdf = None

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        :param param: Type de contenu à générer ('graph' ou 'array')
        """
        if param == "graph":
            self.graph = self._generate_graph()
            logger.info("Graphique généré")
        elif param == "array":
            self.array = self._generate_array()
            logger.info("Tableau généré")

    def _generate_graph(self) -> str:
        """
        Générer un graphique des protocoles
        """
        try:
            protocols = self.capture.sort_network_protocols()

            if not protocols:
                logger.warning("Aucun protocole à afficher dans le graphique")
                return ""

            # Créer un graphique en barres avec Pygal
            bar_chart = pygal.Bar()
            bar_chart.title = 'Distribution des protocoles réseau'
            bar_chart.x_labels = list(protocols.keys())
            bar_chart.add('Nombre de paquets', list(protocols.values()))

            # Sauvegarder le graphique
            graph_filename = "network_protocols_chart.svg"

            # Use configured output dir (pathlib)
            output_dir = Path(project_config.REPORT_OUTPUT_DIR)
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                graph_path = output_dir / graph_filename
            except Exception:
                graph_path = Path(graph_filename)

            bar_chart.render_to_file(str(graph_path))
            logger.info(f"Graphique sauvegardé : {graph_path}")

            return str(graph_path)
        except Exception as e:
            logger.error(f"Erreur lors de la génération du graphique : {e}")
            return ""

    def _generate_array(self) -> str:
        """
        Générer un tableau des protocoles
        """
        try:
            protocols = self.capture.sort_network_protocols()

            if not protocols:
                return "Aucune donnée disponible"

            array_content = "PROTOCOLES CAPTURÉS\n"
            array_content += "=" * 40 + "\n"
            array_content += f"{'Protocole':<20} | {'Paquets':>15}\n"
            array_content += "-" * 40 + "\n"

            for proto, count in protocols.items():
                array_content += f"{proto:<20} | {count:>15}\n"

            array_content += "=" * 40 + "\n\n"

            # Ajouter les informations sur les attaques
            if self.capture.attacks:
                array_content += "ATTAQUES DÉTECTÉES\n"
                array_content += "=" * 40 + "\n"
                array_content += f"{'Type':<20} | {'Source IP':>15}\n"
                array_content += "-" * 40 + "\n"

                for attack in self.capture.attacks:
                    attack_type = attack.get('type', 'Unknown')[:20]
                    src_ip = attack.get('src_ip', 'Unknown')[:15]
                    array_content += f"{attack_type:<20} | {src_ip:>15}\n"

                array_content += "=" * 40 + "\n"

            return array_content
        except Exception as e:
            logger.error(f"Erreur lors de la génération du tableau : {e}")
            return ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title + "\n"
        content += "=" * 60 + "\n\n"
        content += f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        content += self.summary + "\n"
        content += self.array + "\n"

        return content

    def _write_txt(self, path: str) -> None:
        content = self.concat_report()
        if self.graph:
            # normalize path display to POSIX for readability
            try:
                p = Path(self.graph)
                graph_display = p.as_posix()
            except Exception:
                graph_display = str(self.graph)
            content += "\nGraphique généré : " + graph_display + "\n"
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def save(self, filename: str = None, format: str = None) -> None:
        """
        Save report in TXT format only.
        :param filename: Nom du fichier de sortie (si None, use self.filename)
        :param format: ignored; only 'txt' supported
        """
        try:
            if filename is None:
                filename = self.filename

            # default to txt regardless
            format = 'txt'

            # Ensure extension
            base, ext = os.path.splitext(filename)
            if not ext:
                filename = f"{filename}.{format}"
            else:
                # normalize to .txt
                filename = f"{base}.txt"

            # Determine target path using configured output dir
            output_dir = Path(project_config.REPORT_OUTPUT_DIR)
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                primary_path = output_dir / Path(filename).name
            except Exception:
                primary_path = Path(filename)

            # Write TXT
            self._write_txt(str(primary_path))

            logger.info(f"Rapport TXT sauvegardé : {primary_path}")

        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du rapport : {e}")
