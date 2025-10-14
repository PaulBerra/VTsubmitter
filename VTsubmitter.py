#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import hashlib
import json
import logging
import os
import sqlite3
import threading
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

class ThreadSafeCacheManager:
    """
    Gère la base de données de cache SQLite de manière thread-safe.
    Chaque thread obtient sa propre connexion à la base de données pour éviter les conflits
    et les erreurs "core dumped" courantes avec sqlite3 en multithreading.
    """
    def __init__(self, db_path="vt_cache.db"):
        self.db_path = db_path
        self.thread_local = threading.local()
        self._initialize_db()

    def _get_connection(self):
        """Fournit une connexion et un curseur par thread."""
        if not hasattr(self.thread_local, 'connection'):
            self.thread_local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        return self.thread_local.connection

    def _initialize_db(self):
        """Crée la table si elle n'existe pas."""
        conn = self._get_connection()
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                hash TEXT PRIMARY KEY,
                report_json TEXT NOT NULL,
                timestamp DATETIME NOT NULL
            )""")

    def get_report(self, file_hash, expiry_days=30):
        """Récupère un rapport du cache s'il est valide."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT report_json, timestamp FROM reports WHERE hash = ?", (file_hash,))
        result = cursor.fetchone()
        if result:
            report_json, timestamp_str = result
            timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - timestamp < timedelta(days=expiry_days):
                return json.loads(report_json)
        return None

    def set_report(self, file_hash, report):
        """Insère ou met à jour un rapport dans le cache."""
        conn = self._get_connection()
        with conn:
            conn.execute("INSERT OR REPLACE INTO reports (hash, report_json, timestamp) VALUES (?, ?, ?)",
                         (file_hash, json.dumps(report), datetime.now().isoformat()))

    def close(self):
        """
        Ferme la connexion du thread courant.
        Bien que Python ferme les connexions à la sortie, c'est une bonne pratique.
        """
        if hasattr(self.thread_local, 'connection'):
            self.thread_local.connection.close()
            del self.thread_local.connection

def calculate_sha256(filepath):
    """Calcule le hash SHA256 d'un fichier."""
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
    """Interroge l'API VirusTotal pour un hash donné."""
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        # Ajout d'un timeout pour éviter que la requête ne bloque indéfiniment
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            result = response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"status": "Trouvé", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "total_votes": sum(stats.values()), "link": f"https://www.virustotal.com/gui/file/{file_hash}"}
        elif response.status_code == 404:
            return {"status": "Inconnu de VirusTotal"}
        else:
            log.warning(f"Erreur API pour {file_hash}: {response.status_code} - {response.text}")
            return {"status": f"Erreur API ({response.status_code})"}
    except requests.RequestException as e:
        log.error(f"Erreur de connexion pour {file_hash}: {e}")
        return {"status": "Erreur de connexion"}

def process_file(filepath, cache, api_key_cycler, api_key_lock, api_delay, force_rescan, expiry_days):
    """Traite un seul fichier : calcul du hash, vérification du cache, et requête API."""
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
    
    # Rotation des clés API de manière thread-safe
    with api_key_lock:
        api_key = next(api_key_cycler)
    
    time.sleep(api_delay) # Respect du délai de l'API
    
    vt_result = query_virustotal(file_hash, api_key)
    
    if "Erreur" not in vt_result.get("status", ""):
        cache.set_report(file_hash, vt_result)
        
    return {"path": filepath, "hash": file_hash, "vt_result": vt_result}

def write_text_report_entry(report_file, result):
    """Écrit une seule entrée dans le rapport texte."""
    vt = result['vt_result']
    report_file.write(f"Fichier: {result['path']}\n")
    report_file.write(f"Hash: {result['hash']}\n")
    report_file.write(f"Statut: {vt.get('status', 'N/A')}\n")
    if "malicious" in vt:
        report_file.write(f"Détections: {vt.get('malicious', 0)}+{vt.get('suspicious', 0)}/{vt.get('total_votes', 0)}\n")
    report_file.write("-" * 20 + "\n")
    report_file.flush() # Force l'écriture sur le disque

def generate_html_report(results, output_path, folder_path, summary):
    """Génère le rapport HTML complet à partir de la liste des résultats."""
    for r in results:
        if r['vt_result'] and r['vt_result'].get('malicious', 0) > 0:
            r['report_class'] = 'malicious'
        elif r['vt_result'] and r['vt_result'].get('suspicious', 0) > 0:
            r['report_class'] = 'suspicious'
        else:
            r['report_class'] = 'clean'

    # S'assure que le dossier 'templates' existe
    if not Path("templates").is_dir():
        log.critical("Le dossier 'templates' contenant 'report_template.html' est manquant.")
        return

    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    html_content = template.render(
        results=sorted(results, key=lambda x: str(x['path'])),
        folder_path=folder_path,
        report_date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        summary=summary)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except IOError as e:
        log.error(f"Impossible d'écrire le rapport HTML sur {output_path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyseur de fichiers amélioré avec cache thread-safe et rapports incrémentaux.",
        epilog="Lancez le script sans argument de chemin pour un prompt interactif."
    )
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

    if not args.folder_path:
        if not args.silent:
            try:
                path_from_input = input("➡️  Veuillez glisser-déposer le dossier à analyser, puis appuyez sur Entrée :\n> ")
                args.folder_path = path_from_input.strip().strip("'\"")
            except (KeyboardInterrupt, EOFError):
                log.info("\nOpération annulée par l'utilisateur.")
                return
    
    if not args.folder_path:
        log.critical("Aucun dossier à analyser n'a été fourni.")
        return

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
    api_key_lock = threading.Lock() # Verrou pour la rotation des clés
    folder = Path(args.folder_path)
    all_results = []
    excluded_dirs = set(args.exclude_dir or [])
    api_delay = config.getint('virustotal', 'api_delay_seconds', fallback=15)
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
            # --- CORRECTION ---
            # La vérification est maintenant insensible à la casse pour correspondre à des extensions
            # comme .exe, .EXE, .eXe, etc.
            if args.file_extension and not item.name.lower().endswith(f".{args.file_extension.lower()}"):
                continue
            files_to_scan.append(item)

    if not files_to_scan:
        log.warning("Aucun fichier à analyser trouvé.")
        return

    log.info(f"{len(files_to_scan)} fichier(s) à traiter.")
    
    cache = ThreadSafeCacheManager()
    summary = {"total": len(files_to_scan), "processed": 0, "malicious": 0, "suspicious": 0, "clean": 0, "error": 0}

    try:
        with open(args.output_txt, "w", encoding="utf-8") as txt_report, ThreadPoolExecutor(max_workers=4) as executor:
            # Création des en-têtes des rapports
            txt_report.write(f"Rapport d'analyse pour : {folder}\nDate : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
            generate_html_report([], args.output_html, folder, summary)

            futures = {executor.submit(process_file, f, cache, api_key_cycler, api_key_lock, api_delay, args.force_rescan, expiry_days): f for f in files_to_scan}
            
            pbar = tqdm(as_completed(futures), total=len(files_to_scan), desc="Analyse en cours")
            for future in pbar:
                result = future.result()
                summary['processed'] += 1
                if result:
                    all_results.append(result)
                    
                    vt = result.get('vt_result', {})
                    if "Erreur" in vt.get('status', ''):
                        summary['error'] += 1
                    elif vt.get('malicious', 0) > 0:
                        summary['malicious'] += 1
                    elif vt.get('suspicious', 0) > 0:
                        summary['suspicious'] += 1
                    else:
                        summary['clean'] += 1

                    # Écriture incrémentale
                    write_text_report_entry(txt_report, result)
                    generate_html_report(all_results, args.output_html, folder, summary)
                    
                    # Mise à jour de la description de la barre de progression
                    pbar.set_description(f"Analyse: {summary['malicious']} M / {summary['suspicious']} S")
    
    except Exception as e:
        log.critical(f"Une erreur inattendue est survenue: {e}")
    finally:
        cache.close()

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

