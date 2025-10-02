#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import hashlib
import json
import logging
import os
import sqlite3
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from itertools import cycle
from pathlib import Path

import requests
from jinja2 import Environment, FileSystemLoader
from tqdm import tqdm

# --- Configuration du Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

class CacheManager:
    """Gère la base de données de cache SQLite pour chaque thread."""
    def __init__(self, db_path="vt_cache.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            hash TEXT PRIMARY KEY,
            report_json TEXT NOT NULL,
            timestamp DATETIME NOT NULL
        )""")
        self.conn.commit()

    def get_report(self, file_hash, expiry_days=30):
        self.cursor.execute("SELECT report_json, timestamp FROM reports WHERE hash = ?", (file_hash,))
        result = self.cursor.fetchone()
        if result:
            report_json, timestamp_str = result
            timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - timestamp < timedelta(days=expiry_days):
                return json.loads(report_json)
        return None

    def set_report(self, file_hash, report):
        self.cursor.execute("INSERT OR REPLACE INTO reports (hash, report_json, timestamp) VALUES (?, ?, ?)",
                            (file_hash, json.dumps(report), datetime.now().isoformat()))
        self.conn.commit()

    def close(self):
        self.conn.close()

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(8192), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError as e:
        log.warning(f"Impossible de lire le fichier {filepath}: {e}")
        return None

def query_virustotal(file_hash, api_key):
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"status": "Trouvé", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "total_votes": sum(stats.values()), "link": f"https://www.virustotal.com/gui/file/{file_hash}"}
        elif response.status_code == 404:
            return {"status": "Inconnu de VirusTotal"}
        else:
            return {"status": f"Erreur API ({response.status_code})"}
    except requests.RequestException as e:
        log.error(f"Erreur de connexion pour {file_hash}: {e}")
        return {"status": "Erreur de connexion"}

def process_file(filepath, cache, api_key_cycler, api_delay, force_rescan, expiry_days):
    log.debug(f"Traitement de {filepath}")
    file_hash = calculate_sha256(filepath)
    if not file_hash:
        return None

    if not force_rescan:
        cached_report = cache.get_report(file_hash, expiry_days)
        if cached_report:
            log.debug(f"Résultat trouvé dans le cache pour {file_hash}")
            return {"path": filepath, "hash": file_hash, "vt_result": cached_report}

    log.debug(f"Interrogation de l'API pour {file_hash}")
    time.sleep(api_delay)
    api_key = next(api_key_cycler)
    vt_result = query_virustotal(file_hash, api_key)
    
    if "Erreur" not in vt_result.get("status", ""):
        cache.set_report(file_hash, vt_result)
        
    return {"path": filepath, "hash": file_hash, "vt_result": vt_result}

def generate_html_report(results, output_path, folder_path, summary):
    for r in results:
        if r['vt_result'] and r['vt_result'].get('malicious', 0) > 0:
            r['report_class'] = 'malicious'
        elif r['vt_result'] and r['vt_result'].get('suspicious', 0) > 0:
            r['report_class'] = 'suspicious'
        else:
            r['report_class'] = 'clean'

    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    html_content = template.render(
        results=sorted(results, key=lambda x: str(x['path'])),
        folder_path=folder_path,
        report_date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        summary=summary)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(
        description="Analyseur de fichiers amélioré avec cache et multithreading.",
        epilog="Lancez le script sans argument de chemin pour un prompt interactif."
    )
    # Le chemin du dossier est maintenant optionnel (nargs='?')
    parser.add_argument("folder_path", nargs='?', default=None, help="Chemin du dossier à analyser (optionnel).")
    parser.add_argument("file_extension", nargs='?', default=None, help="Extension (optionnel: scan de tous les fichiers).")
    parser.add_argument("-c", "--config", default="config.ini", help="Chemin du fichier de configuration.")
    parser.add_argument("-o", "--output-txt", default="report.txt", help="Nom du fichier de rapport texte.")
    parser.add_argument("-H", "--output-html", default="report.html", help="Nom du fichier de rapport HTML.")
    parser.add_argument("--exclude-dir", nargs='+', help="Noms de dossiers à exclure de l'analyse.")
    parser.add_argument("--force-rescan", action="store_true", help="Force une nouvelle analyse sans utiliser le cache.")
    
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-v", "--verbose", action="store_true", help="Affiche les logs de débogage.")
    verbosity_group.add_argument("-s", "--silent", action="store_true", help="N'affiche que les erreurs critiques.")
    
    args = parser.parse_args()

    # --- NOUVEAU BLOC : GESTION DU CHEMIN INTERACTIF ---
    if not args.folder_path:
        if not args.silent:
            try:
                # Affiche le message et attend l'entrée de l'utilisateur
                path_from_input = input("➡️  Veuillez glisser-déposer le dossier à analyser dans le terminal, puis appuyez sur Entrée :\n> ")
                # Nettoie le chemin (enlève les espaces et les guillemets/apostrophes)
                args.folder_path = path_from_input.strip().strip("'\"")
            except (KeyboardInterrupt, EOFError):
                log.info("\nOpération annulée par l'utilisateur.")
                return
    
    if not args.folder_path:
        log.critical("Aucun dossier à analyser n'a été fourni.")
        return
    # --- FIN DU NOUVEAU BLOC ---

    if args.verbose: log.setLevel(logging.DEBUG)
    if args.silent: log.setLevel(logging.CRITICAL)

    config = configparser.ConfigParser()
    if not Path(args.config).is_file():
        log.critical(f"Fichier de configuration '{args.config}' non trouvé.")
        return
    config.read(args.config)

    api_keys = [key.strip() for key in config.get('virustotal', 'api_keys', fallback='').split(',') if key.strip()]
    if not api_keys or "VOTRE" in api_keys[0]:
        log.critical("Aucune clé API valide trouvée dans config.ini. Veuillez éditer le fichier.")
        return

    api_key_cycler = cycle(api_keys)
    folder = Path(args.folder_path)
    all_results = []
    excluded_dirs = set(args.exclude_dir or [])
    api_delay = config.getint('virustotal', 'api_delay_seconds', fallback=16)
    expiry_days = config.getint('settings', 'cache_expiry_days', fallback=30)
    
    if not folder.is_dir():
        log.critical(f"Le chemin '{folder}' n'est pas un dossier valide.")
        return
    
    log.info(f"Analyse du dossier : {folder}")
    
    files_to_scan = []
    for item in folder.rglob('*'):
        if item.is_file():
            if any(excluded in item.parts for excluded in excluded_dirs):
                log.debug(f"Exclusion du fichier : {item}")
                continue
            if args.file_extension and item.suffix != f".{args.file_extension}":
                continue
            files_to_scan.append(item)

    if not files_to_scan:
        log.warning("Aucun fichier à analyser trouvé.")
        return

    log.info(f"{len(files_to_scan)} fichier(s) à traiter.")
    
    cache = CacheManager()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(process_file, f, cache, api_key_cycler, api_delay, args.force_rescan, expiry_days): f for f in files_to_scan}
        
        for future in tqdm(as_completed(futures), total=len(files_to_scan), desc="Analyse en cours"):
            result = future.result()
            if result:
                all_results.append(result)
    cache.close()

    log.info("Génération des rapports...")
    summary = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}
    with open(args.output_txt, "w", encoding="utf-8") as txt_report:
        for res in sorted(all_results, key=lambda x: str(x['path'])):
            summary['total'] += 1
            vt = res['vt_result']
            if vt.get('malicious', 0) > 0: summary['malicious'] += 1
            elif vt.get('suspicious', 0) > 0: summary['suspicious'] += 1
            else: summary['clean'] += 1
            
            txt_report.write(f"Fichier: {res['path']}\nHash: {res['hash']}\nStatut: {vt['status']}\n")
            if "malicious" in vt:
                txt_report.write(f"Détections: {vt['malicious']}+{vt['suspicious']}/{vt['total_votes']}\n")
            txt_report.write("-" * 20 + "\n")

    generate_html_report(all_results, args.output_html, folder, summary)
    
    log.info("Analyse terminée.")
    log.info(f"Rapport texte : {args.output_txt}")
    log.info(f"Rapport HTML : {args.output_html}")
    
    if not args.silent:
        try:
            report_path = os.path.abspath(args.output_html)
            webbrowser.open(f"file://{report_path}")
            log.info(f"Ouverture du rapport HTML dans votre navigateur.")
        except Exception:
            log.warning("Impossible d'ouvrir le rapport automatiquement.")

if __name__ == "__main__":
    main()