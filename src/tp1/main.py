from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report
from src import config as project_config
from pathlib import Path


def main():
    logger.info("=" * 60)
    logger.info("DÉMARRAGE DU PROGRAMME IDS/IPS")
    logger.info("=" * 60)

    try:
        # Étape 1 : Créer une instance de Capture
        capture = Capture()

        if capture.interface is None:
            logger.error("Impossible de procéder sans interface réseau")
            return

        # Étape 2 : Capturer le trafic (50 paquets avec timeout de 30 secondes)
        logger.info("\n[ÉTAPE 1/4] Capture du trafic réseau...")
        capture.capture_traffic(packet_count=50, timeout=30)

        # Étape 3 : Analyser le trafic
        logger.info("\n[ÉTAPE 2/4] Analyse du trafic...")
        capture.analyse("tcp")

        # Étape 4 : Récupérer le résumé
        logger.info("\n[ÉTAPE 3/4] Génération du résumé...")
        summary = capture.get_summary()

        # Étape 5 : Créer le rapport TXT
        logger.info("\n[ÉTAPE 4/4] Génération du rapport TXT...")
        # Use a basename (no extension); Report.save will write .txt into REPORT_OUTPUT_DIR
        filename = "report"
        report = Report(capture, filename, summary)

        # Générer le graphique et le tableau
        report.generate("graph")
        report.generate("array")

        # Sauvegarder le rapport (TXT dans le dossier configuré)
        report.save(filename)

        # Format path for display
        output_dir = Path(project_config.REPORT_OUTPUT_DIR)
        output_file = (output_dir / f"{filename}.txt").as_posix()

        logger.info("\n" + "=" * 60)
        logger.info(f"✓ Programme terminé avec succès !")
        logger.info(f"✓ Rapport sauvegardé dans : {output_file}")
        logger.info("=" * 60)

    except KeyboardInterrupt:
        logger.warning("\nProgramme interrompu par l'utilisateur")
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution : {e}", exc_info=True)


if __name__ == "__main__":
    main()
