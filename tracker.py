#!/usr/bin/env python3
"""
Suivi anonyme des appels d'offres sur marchespublics.gov.ma
Surveille les changements sur les pages publiques et explore les endpoints cachés.
Aucune authentification requise.
"""

import argparse
import csv
import json
import os
import re
import signal
import sys
import time
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager


# ── Couleurs console ──────────────────────────────────────────────────────────

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"


# ── Etat d'une consultation ──────────────────────────────────────────────────

class ConsultationState:
    def __init__(self):
        self.reference = ""
        self.objet = ""
        self.date_limite = ""
        self.statut = ""
        self.organisme = ""
        self.tabs = {}  # {tab_name: {"text": str, "rows": list}}
        self.page_hash = ""  # hash of full page text for quick change detection


# ── Tracker anonyme ──────────────────────────────────────────────────────────

BASE_URL = "https://www.marchespublics.gov.ma"
TAB_NAMES = ["Publicité", "Question", "Groupement", "Dépôt", "Messagerie"]


class PublicTracker:
    def __init__(self, refs, org=None, interval=120, headless=True, csv_path="tracker_log.csv"):
        self.refs = refs
        self.org = org
        self.interval = interval
        self.headless = headless
        self.csv_path = csv_path
        self.driver = None
        self.previous_states = {}
        self._running = True

    # ── Browser setup ──

    def start_browser(self, enable_network_logging=False):
        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1920,1080")
        opts.add_argument("--lang=fr-FR")
        opts.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        # Reduce bot detection
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])

        if enable_network_logging:
            opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=opts)
        except Exception:
            self.driver = webdriver.Chrome(options=opts)

        self.driver.set_page_load_timeout(30)
        self.driver.implicitly_wait(5)

        # Remove webdriver flag
        self.driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"},
        )

    def stop_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    # ── URL construction ──

    def _build_url(self, ref, org=None):
        url = f"{BASE_URL}/index.php?page=entreprise.EntrepriseDetailsConsultation&refConsultation={ref}"
        if org:
            url += f"&orgAcronyme={org}"
        return url

    # ── Page loading with retry ──

    def _load_page(self, url, max_retries=3):
        for attempt in range(max_retries):
            try:
                self.driver.get(url)
                # Wait for PRADO to render content
                WebDriverWait(self.driver, 15).until(
                    EC.presence_of_element_located(
                        (By.XPATH, "//td[contains(text(),'Référence') or contains(text(),'Reference')]"
                                   " | //span[contains(text(),'Référence')]"
                                   " | //div[@id='content']"
                                   " | //table")
                    )
                )
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"{Colors.YELLOW}  Tentative {attempt+1}/{max_retries} echouee. "
                          f"Retry dans {wait}s...{Colors.RESET}")
                    time.sleep(wait)
                else:
                    print(f"{Colors.RED}  Echec chargement apres {max_retries} tentatives: {e}{Colors.RESET}")
                    return False

    # ── Header extraction ──

    def _extract_header(self):
        info = {"reference": "", "objet": "", "date_limite": "", "statut": "", "organisme": ""}
        try:
            page = self.driver.page_source

            # Reference
            m = re.search(r"R[ée]f[ée]rence\s*:?\s*</[^>]+>\s*([^<]+)", page)
            if not m:
                m = re.search(r"R[ée]f[ée]rence\s*:?\s*([^<\n]+)", page)
            if m:
                info["reference"] = m.group(1).strip()

            # Objet
            m = re.search(r"Objet\s*(?:de la consultation)?\s*:?\s*</[^>]+>\s*([^<]+)", page)
            if not m:
                m = re.search(r"Objet\s*:?\s*([^<\n]+)", page)
            if m:
                info["objet"] = m.group(1).strip()

            # Date limite
            m = re.search(r"Date\s+et\s+heure\s+limite[^:]*:\s*</[^>]+>\s*([^<]+)", page)
            if not m:
                m = re.search(r"Date\s+et\s+heure\s+limite[^:]*:\s*([^<\n]+)", page)
            if m:
                info["date_limite"] = m.group(1).strip()

            # Try to extract via Selenium as fallback
            if not info["reference"]:
                try:
                    cells = self.driver.find_elements(
                        By.XPATH, "//td[contains(text(),'Référence')]/following-sibling::td"
                    )
                    if cells:
                        info["reference"] = cells[0].text.strip()
                except Exception:
                    pass

            if not info["objet"]:
                try:
                    cells = self.driver.find_elements(
                        By.XPATH, "//td[contains(text(),'Objet')]/following-sibling::td"
                    )
                    if cells:
                        info["objet"] = cells[0].text.strip()
                except Exception:
                    pass

            if not info["date_limite"]:
                try:
                    cells = self.driver.find_elements(
                        By.XPATH, "//td[contains(text(),'Date et heure limite')]/following-sibling::td"
                    )
                    if cells:
                        info["date_limite"] = cells[0].text.strip()
                except Exception:
                    pass

        except Exception:
            pass
        return info

    # ── Tab interaction ──

    def _click_tab(self, tab_name):
        try:
            selectors = [
                f"//a[contains(text(), '{tab_name}')]",
                f"//td[contains(text(), '{tab_name}')]",
                f"//div[contains(text(), '{tab_name}')]",
                f"//span[contains(text(), '{tab_name}')]",
                f"//*[contains(@class, 'tab') and contains(text(), '{tab_name}')]",
                f"//li[contains(text(), '{tab_name}')]",
            ]
            for sel in selectors:
                elems = self.driver.find_elements(By.XPATH, sel)
                if elems:
                    elems[0].click()
                    time.sleep(2)
                    return True
        except Exception:
            pass
        return False

    def _extract_table_rows(self):
        rows_data = []
        try:
            tables = self.driver.find_elements(By.TAG_NAME, "table")
            for table in tables:
                # Skip tiny nav tables
                if table.size.get("height", 0) < 30:
                    continue
                rows = table.find_elements(By.TAG_NAME, "tr")
                for row in rows[1:]:
                    cells = row.find_elements(By.TAG_NAME, "td")
                    if len(cells) >= 2:
                        cell_texts = [c.text.strip() for c in cells]
                        if any(cell_texts):
                            rows_data.append(cell_texts)
        except Exception:
            pass
        return rows_data

    def _extract_tab_content(self, tab_name):
        result = {"clicked": False, "text": "", "rows": []}
        if not self._click_tab(tab_name):
            return result
        result["clicked"] = True

        try:
            # Get the visible body text after tab click
            body_text = self.driver.find_element(By.TAG_NAME, "body").text
            # Try to isolate just the tab panel content
            panels = self.driver.find_elements(
                By.CSS_SELECTOR,
                ".tab-pane.active, .panel-body, [style*='display: block'], .content-panel"
            )
            if panels:
                result["text"] = "\n".join(p.text.strip() for p in panels if p.text.strip())
            else:
                result["text"] = body_text
        except Exception:
            pass

        result["rows"] = self._extract_table_rows()
        return result

    # ── CDP network logging (discovery mode) ──

    def _get_network_logs(self):
        requests = []
        try:
            logs = self.driver.get_log("performance")
            for entry in logs:
                try:
                    log_data = json.loads(entry["message"])
                    msg = log_data.get("message", {})
                    method = msg.get("method", "")

                    if method == "Network.requestWillBeSent":
                        params = msg.get("params", {})
                        req = params.get("request", {})
                        requests.append({
                            "url": req.get("url", ""),
                            "method": req.get("method", ""),
                            "type": params.get("type", ""),
                            "initiator_type": params.get("initiator", {}).get("type", ""),
                            "post_data": req.get("postData", ""),
                        })

                    elif method == "Network.responseReceived":
                        params = msg.get("params", {})
                        resp = params.get("response", {})
                        url = resp.get("url", "")
                        status = resp.get("status", 0)
                        # Attach status to matching request
                        for r in reversed(requests):
                            if r["url"] == url and "status" not in r:
                                r["status"] = status
                                break
                except Exception:
                    continue
        except Exception:
            pass
        return requests

    # ── Discovery mode ──

    def _probe_url(self, url, label=""):
        result = {"url": url, "label": label, "accessible": False, "redirected": False,
                  "redirect_url": "", "content_preview": "", "has_data": False}
        try:
            self.driver.get(url)
            time.sleep(3)

            current = self.driver.current_url
            if current != url:
                result["redirected"] = True
                result["redirect_url"] = current

            page_text = self.driver.find_element(By.TAG_NAME, "body").text[:1000]
            result["content_preview"] = page_text

            # Check if we got real content vs error/login page
            error_indicators = [
                "Vous n'êtes pas authentifié",
                "S'identifier",
                "Erreur",
                "403",
                "Page introuvable",
                "Accès refusé",
            ]
            login_redirect = any(ind.lower() in page_text.lower() for ind in error_indicators)

            if not login_redirect and len(page_text) > 100:
                result["accessible"] = True
                # Check for interesting data
                data_indicators = ["retrait", "dépôt", "depot", "nombre", "entreprise", "ICE"]
                if any(ind.lower() in page_text.lower() for ind in data_indicators):
                    result["has_data"] = True

        except Exception as e:
            result["content_preview"] = f"ERREUR: {e}"

        return result

    def run_discovery(self):
        ref = self.refs[0]
        org = self.org
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"discovery_report_{ref}_{timestamp}.txt"
        findings = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  MODE DISCOVERY - Exploration du portail{Colors.RESET}")
        print(f"{Colors.BOLD}  Consultation: {ref}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")

        self.start_browser(enable_network_logging=True)
        try:
            # ── Phase 1: Load public page and capture network ──
            print(f"{Colors.CYAN}[1/5] Chargement de la page publique...{Colors.RESET}")
            url = self._build_url(ref, org)
            self._load_page(url)

            header = self._extract_header()
            findings.append("=== INFORMATIONS CONSULTATION ===")
            findings.append(f"URL: {url}")
            findings.append(f"Reference: {header.get('reference', 'N/A')}")
            findings.append(f"Objet: {header.get('objet', 'N/A')}")
            findings.append(f"Date limite: {header.get('date_limite', 'N/A')}")
            findings.append("")

            initial_requests = self._get_network_logs()
            findings.append(f"=== REQUETES RESEAU AU CHARGEMENT ({len(initial_requests)}) ===")
            for r in initial_requests:
                if BASE_URL in r.get("url", "") or "marchespublics" in r.get("url", ""):
                    findings.append(f"  {r['method']} {r['url'][:120]}")
                    if r.get("post_data"):
                        findings.append(f"    POST data: {r['post_data'][:200]}")
            findings.append("")

            print(f"  {len(initial_requests)} requetes reseau capturees")

            # ── Phase 2: Click each tab and capture XHR ──
            print(f"\n{Colors.CYAN}[2/5] Exploration des onglets...{Colors.RESET}")
            findings.append("=== CONTENU DES ONGLETS ===")

            for tab in TAB_NAMES:
                print(f"  Onglet: {tab}...", end=" ")
                # Clear previous logs
                self._get_network_logs()

                content = self._extract_tab_content(tab)

                # Capture network calls triggered by tab click
                tab_requests = self._get_network_logs()
                xhr_calls = [r for r in tab_requests
                             if r.get("initiator_type") in ("script", "xmlhttprequest", "fetch")]

                findings.append(f"\n--- Onglet: {tab} ---")
                findings.append(f"  Clique reussi: {content['clicked']}")
                text_preview = content["text"][:300] if content["text"] else "(vide)"
                findings.append(f"  Contenu: {text_preview}")
                findings.append(f"  Lignes tableau: {len(content['rows'])}")
                findings.append(f"  Requetes XHR declenchees: {len(xhr_calls)}")

                for r in xhr_calls:
                    findings.append(f"    {r['method']} {r['url'][:120]}")
                    if r.get("post_data"):
                        findings.append(f"      POST: {r['post_data'][:300]}")

                status = "OK" if content["clicked"] else "ECHEC"
                has_content = "contenu" if content["text"] and "aucun" not in content["text"].lower() else "vide"
                print(f"[{status}] [{has_content}] [{len(xhr_calls)} XHR]")

            findings.append("")

            # ── Phase 3: Probe agent URLs without auth ──
            print(f"\n{Colors.CYAN}[3/5] Sondage des URLs agent sans authentification...{Colors.RESET}")
            findings.append("=== SONDAGE URLs AGENT (SANS AUTH) ===")

            probe_urls = [
                (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}", "GestionRegistres (sans type)"),
            ]
            for t in range(1, 11):
                probe_urls.append(
                    (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type={t}",
                     f"GestionRegistres type={t}")
                )
            # Additional URL patterns to try
            probe_urls.extend([
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch", "Recherche avancee"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseConsultationList", "Liste consultations"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseResultats&refConsultation={ref}",
                 "Resultats consultation"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseRegistres&ref={ref}", "Registres entreprise"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseRegistres&refConsultation={ref}",
                 "Registres entreprise v2"),
            ])

            for probe_url, label in probe_urls:
                print(f"  {label}...", end=" ")
                result = self._probe_url(probe_url, label)

                findings.append(f"\n--- {label} ---")
                findings.append(f"  URL: {result['url']}")
                findings.append(f"  Accessible: {result['accessible']}")
                if result["redirected"]:
                    findings.append(f"  Redirige vers: {result['redirect_url']}")
                if result["has_data"]:
                    findings.append(f"  *** DONNEES TROUVEES ***")
                findings.append(f"  Apercu: {result['content_preview'][:200]}")

                if result["has_data"]:
                    print(f"{Colors.GREEN}DONNEES TROUVEES!{Colors.RESET}")
                elif result["accessible"]:
                    print(f"{Colors.YELLOW}accessible (pas de donnees bidder){Colors.RESET}")
                else:
                    print(f"{Colors.DIM}bloque/redirige{Colors.RESET}")

                time.sleep(2)  # Avoid hammering the server

            findings.append("")

            # ── Phase 4: Analyze PRADO callbacks ──
            print(f"\n{Colors.CYAN}[4/5] Analyse des callbacks PRADO...{Colors.RESET}")
            findings.append("=== ANALYSE PRADO ===")

            # Reload the consultation page to get fresh PRADO state
            self._load_page(url)
            page_source = self.driver.page_source

            # Extract PRADO_PAGESTATE
            pagestate_match = re.search(r'PRADO_PAGESTATE["\s]*(?:value="|:)["\s]*([^"]+)"', page_source)
            if pagestate_match:
                pagestate = pagestate_match.group(1)
                findings.append(f"  PRADO_PAGESTATE trouve (longueur: {len(pagestate)})")
                findings.append(f"  Debut: {pagestate[:80]}...")
            else:
                pagestate = None
                findings.append("  PRADO_PAGESTATE non trouve dans la page")

            # Extract callback IDs
            callback_ids = re.findall(r'__CALLBACKID["\s]*(?:value="|:)["\s]*([^"]+)"', page_source)
            if callback_ids:
                findings.append(f"  Callback IDs trouves: {callback_ids}")
            else:
                findings.append("  Aucun CALLBACKID explicite trouve")

            # Look for Prado client-side scripts
            prado_scripts = re.findall(r'Prado\.WebServices\.TActiveCallback\([^)]+\)', page_source)
            findings.append(f"  Scripts PRADO TActiveCallback: {len(prado_scripts)}")
            for ps in prado_scripts[:5]:
                findings.append(f"    {ps[:150]}")

            # Look for any hidden form fields or data
            hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', page_source)
            findings.append(f"\n  Champs caches: {len(hidden_inputs)}")
            for hi in hidden_inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', hi)
                value_match = re.search(r'value=["\']([^"\']*)["\']', hi)
                if name_match:
                    name = name_match.group(1)
                    value = value_match.group(1)[:80] if value_match else ""
                    findings.append(f"    {name} = {value}")

            findings.append("")

            # ── Phase 5: Save page source for manual inspection ──
            print(f"\n{Colors.CYAN}[5/5] Sauvegarde du code source pour inspection...{Colors.RESET}")
            source_path = f"page_source_{ref}_{timestamp}.html"
            with open(source_path, "w", encoding="utf-8") as f:
                f.write(page_source)
            findings.append(f"=== CODE SOURCE ===")
            findings.append(f"  Sauvegarde dans: {source_path}")
            findings.append(f"  Taille: {len(page_source)} caracteres")

            # ── Write report ──
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"Discovery Report - {ref}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"{'=' * 60}\n\n")
                f.write("\n".join(findings))

            print(f"\n{Colors.BOLD}{Colors.GREEN}{'=' * 60}{Colors.RESET}")
            print(f"{Colors.GREEN}  Rapport sauvegarde: {report_path}{Colors.RESET}")
            print(f"{Colors.GREEN}  Source HTML: {source_path}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'=' * 60}{Colors.RESET}")

            # Summary
            print(f"\n{Colors.BOLD}Resume:{Colors.RESET}")
            data_urls = [f for f in findings if "DONNEES TROUVEES" in f]
            if data_urls:
                print(f"  {Colors.GREEN}{len(data_urls)} endpoint(s) avec donnees accessibles!{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}Aucun endpoint avec donnees bidder trouve sans auth.{Colors.RESET}")
                print(f"  Les donnees de retraits/depots sont protegees par l'authentification agent.")

        finally:
            self.stop_browser()

    # ── Monitor mode: scraping ──

    def scrape_public(self, ref, org=None):
        state = ConsultationState()

        url = self._build_url(ref, org)
        if not self._load_page(url):
            return state

        # Header
        header = self._extract_header()
        state.reference = header.get("reference", ref)
        state.objet = header.get("objet", "")
        state.date_limite = header.get("date_limite", "")
        state.statut = header.get("statut", "")
        state.organisme = header.get("organisme", "")

        # Tabs
        for tab in TAB_NAMES:
            state.tabs[tab] = self._extract_tab_content(tab)

        # Page hash for quick change detection
        try:
            full_text = self.driver.find_element(By.TAG_NAME, "body").text
            state.page_hash = str(hash(full_text))
        except Exception:
            state.page_hash = ""

        return state

    # ── Change detection ──

    def _compare_states(self, old, new):
        changes = []
        if old is None:
            return [("INITIAL", "Premier scan", "")]

        if old.date_limite != new.date_limite:
            changes.append(("DATE_LIMITE", f"{old.date_limite} -> {new.date_limite}", ""))

        if old.statut != new.statut and (old.statut or new.statut):
            changes.append(("STATUT", f"{old.statut} -> {new.statut}", ""))

        if old.objet != new.objet and (old.objet or new.objet):
            changes.append(("OBJET", f"Modifie", f"{old.objet} -> {new.objet}"))

        # Compare tab contents
        for tab in TAB_NAMES:
            old_text = old.tabs.get(tab, {}).get("text", "")
            new_text = new.tabs.get(tab, {}).get("text", "")
            old_rows = old.tabs.get(tab, {}).get("rows", [])
            new_rows = new.tabs.get(tab, {}).get("rows", [])

            if old_text != new_text:
                changes.append((f"ONGLET_{tab.upper()}", "Contenu modifie", ""))
            if len(old_rows) != len(new_rows):
                diff = len(new_rows) - len(old_rows)
                sign = "+" if diff > 0 else ""
                changes.append((f"TABLEAU_{tab.upper()}", f"{len(old_rows)} -> {len(new_rows)} lignes ({sign}{diff})", ""))

        return changes

    # ── CSV logging ──

    def _log_to_csv(self, ref, state, changes):
        file_exists = os.path.isfile(self.csv_path)
        try:
            with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow([
                        "timestamp", "reference", "objet", "date_limite", "statut",
                        "tabs_summary", "changes"
                    ])
                tabs_summary = "; ".join(
                    f"{t}: {'contenu' if state.tabs.get(t, {}).get('text', '') else 'vide'}"
                    for t in TAB_NAMES
                )
                changes_str = "; ".join(f"{c[0]}: {c[1]}" for c in changes)
                writer.writerow([
                    datetime.now().isoformat(), ref, state.objet[:100],
                    state.date_limite, state.statut, tabs_summary, changes_str
                ])
        except Exception as e:
            print(f"{Colors.RED}  Erreur CSV: {e}{Colors.RESET}")

    # ── Display ──

    def display_header(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{'=' * 60}")
        print(f"{Colors.BOLD}  [{now}] Suivi AO - marchespublics.gov.ma (anonyme){Colors.RESET}")
        print(f"{'=' * 60}")

    def display_state(self, ref, state, prev, changes):
        print()
        label = state.reference or ref
        print(f"{Colors.BOLD}{Colors.CYAN}  {label}{Colors.RESET}")
        if state.objet:
            print(f"  {state.objet}")
        if state.date_limite:
            print(f"  Date limite : {state.date_limite}")
        if state.statut:
            print(f"  Statut      : {state.statut}")
        print(f"  {'─' * 50}")

        # Tab summaries
        for tab in TAB_NAMES:
            tab_data = state.tabs.get(tab, {})
            text = tab_data.get("text", "")
            rows = tab_data.get("rows", [])

            if text:
                preview = text[:80].replace("\n", " ")
                if len(text) > 80:
                    preview += "..."
            else:
                preview = "(vide)"

            # Check if this tab changed
            old_text = ""
            if prev:
                old_text = prev.tabs.get(tab, {}).get("text", "")

            if prev and text != old_text:
                print(f"  {tab:12s}: {Colors.GREEN}{preview} *** MODIFIE ***{Colors.RESET}")
            else:
                print(f"  {tab:12s}: {Colors.DIM}{preview}{Colors.RESET}")

            if rows:
                print(f"  {'':12s}  {len(rows)} ligne(s) dans le tableau")

        # Show changes
        if changes and changes[0][0] != "INITIAL":
            print(f"\n  {Colors.BOLD}{Colors.GREEN}!! CHANGEMENTS DETECTES:{Colors.RESET}")
            for change_type, change_desc, detail in changes:
                print(f"  {Colors.GREEN}  {change_type}: {change_desc}{Colors.RESET}")
                if detail:
                    print(f"  {Colors.DIM}    {detail}{Colors.RESET}")

    # ── Main monitor loop ──

    def run_monitor(self):
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

        print(f"\n{Colors.BOLD}Demarrage du monitoring anonyme...{Colors.RESET}")
        print(f"  Consultations: {', '.join(self.refs)}")
        print(f"  Intervalle: {self.interval}s")
        print(f"  CSV: {self.csv_path}")
        print(f"  Headless: {self.headless}\n")

        self.start_browser(enable_network_logging=False)
        try:
            cycle = 0
            while self._running:
                cycle += 1
                self.display_header()
                print(f"{Colors.DIM}  Cycle #{cycle}{Colors.RESET}")

                for ref in self.refs:
                    try:
                        state = self.scrape_public(ref, self.org)
                        prev = self.previous_states.get(ref)
                        changes = self._compare_states(prev, state)
                        self.display_state(ref, state, prev, changes)

                        if changes:
                            self._log_to_csv(ref, state, changes)

                        self.previous_states[ref] = state
                    except Exception as e:
                        print(f"\n{Colors.RED}  Erreur pour {ref}: {e}{Colors.RESET}")

                print(f"\n{'=' * 60}")
                print(
                    f"{Colors.DIM}  Prochain rafraichissement dans {self.interval}s "
                    f"(Ctrl+C pour arreter){Colors.RESET}"
                )
                print(f"{'=' * 60}")

                for _ in range(self.interval):
                    if not self._running:
                        break
                    time.sleep(1)

        finally:
            self.stop_browser()

    def _handle_exit(self, signum, frame):
        print(f"\n{Colors.YELLOW}Arret en cours...{Colors.RESET}")
        self._running = False


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Suivi anonyme des appels d'offres - marchespublics.gov.ma"
    )
    parser.add_argument(
        "--ref", required=True,
        help="Reference(s) de consultation, separees par des virgules (ex: 979388,979400)"
    )
    parser.add_argument(
        "--org", default=None,
        help="orgAcronyme pour l'URL (ex: e14)"
    )
    parser.add_argument(
        "--interval", type=int, default=120,
        help="Intervalle de rafraichissement en secondes (defaut: 120)"
    )
    parser.add_argument(
        "--discover", action="store_true",
        help="Mode discovery: explore le portail pour trouver des donnees cachees (execution unique)"
    )
    parser.add_argument(
        "--no-headless", action="store_true",
        help="Afficher le navigateur (mode non-headless)"
    )
    parser.add_argument(
        "--csv-log", default="tracker_log.csv",
        help="Chemin vers le fichier CSV de log (defaut: tracker_log.csv)"
    )
    args = parser.parse_args()

    refs = [r.strip() for r in args.ref.split(",")]
    headless = not args.no_headless

    tracker = PublicTracker(
        refs=refs,
        org=args.org,
        interval=args.interval,
        headless=headless,
        csv_path=args.csv_log,
    )

    if args.discover:
        tracker.run_discovery()
    else:
        tracker.run_monitor()


if __name__ == "__main__":
    main()
