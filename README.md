# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install --no-root
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

## Rapports générés

Les rapports produits par le TP sont maintenant générés dans un dossier configurable.

- Le dossier par défaut est `tests/tp1/utils/output` (configurable dans `src/config.py` via la variable `REPORT_OUTPUT_DIR`).
- La méthode `Report.save()` produit un fichier texte (`.txt`) contenant le rapport. Le format TXT est suffisant pour nos besoins actuels.

Exemple rapide :

```python
from src.tp1.utils.report import Report

report = Report(capture, "rapport", "Résumé de l'analyse")
report.generate("array")
report.generate("graph")
report.save("rapport")  # génère tests/tp1/utils/output/rapport.txt
```

Si besoin, on peut changer la destination globale en éditant `src/config.py`.
