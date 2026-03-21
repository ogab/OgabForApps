#!/usr/bin/env python3
"""
Suivi en temps réel des soumissionnaires sur marchespublics.gov.ma
Surveille les retraits, dépôts électroniques et questions pour un ou plusieurs appels d'offres.
"""

import argparse
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


# ── Données d'un AO ──────────────────────────────────────────────────────────

class ConsultationState:
    def __init__(self):
        self.reference = ""
        self.objet = ""
        self.date_limite = ""
        self.nb_retraits = 0
        self.nb_depots = 0
        self.nb_questions = 0
        self.retraits = []   # list of dicts
        self.depots = []     # list of dicts
        self.questions = []  # list of dicts


# ── Tracker ───────────────────────────────────────────────────────────────────

class BidderTracker:
    def __init__(self, config):
        self.config = config
        self.driver = None
        self.previous_states = {}  # ref -> ConsultationState
        self._running = True

    # ── Setup ──

    def start_browser(self):
        opts = Options()
        if self.config.get("headless", True):
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

        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=opts)
        except Exception:
            # Fallback: try system chromedriver
            self.driver = webdriver.Chrome(options=opts)

        self.driver.set_page_load_timeout(30)
        self.driver.implicitly_wait(5)

    def stop_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    # ── Login ──

    def login(self):
        base = self.config["base_url"]
        username = self.config["username"]
        password = self.config["password"]

        print(f"{Colors.CYAN}Connexion au portail...{Colors.RESET}")
        self.driver.get(base)
        time.sleep(2)

        # Try to find and click login link/button
        try:
            # Look for common login patterns on the portal
            login_selectors = [
                "//a[contains(@href, 'Connexion')]",
                "//a[contains(@href, 'connexion')]",
                "//a[contains(@href, 'Login')]",
                "//a[contains(@href, 'login')]",
                "//a[contains(text(), 'Connexion')]",
                "//a[contains(text(), 'Se connecter')]",
                "//input[@type='submit' and contains(@value, 'Connexion')]",
            ]
            for sel in login_selectors:
                elems = self.driver.find_elements(By.XPATH, sel)
                if elems:
                    elems[0].click()
                    time.sleep(2)
                    break
        except Exception:
            pass

        # Fill login form
        filled = False
        username_selectors = [
            (By.NAME, "login"),
            (By.NAME, "username"),
            (By.NAME, "utilisateur"),
            (By.ID, "login"),
            (By.ID, "username"),
            (By.CSS_SELECTOR, "input[type='text']"),
        ]
        password_selectors = [
            (By.NAME, "password"),
            (By.NAME, "motDePasse"),
            (By.NAME, "mdp"),
            (By.ID, "password"),
            (By.CSS_SELECTOR, "input[type='password']"),
        ]

        for u_by, u_sel in username_selectors:
            try:
                user_field = self.driver.find_element(u_by, u_sel)
                user_field.clear()
                user_field.send_keys(username)
                filled = True
                break
            except Exception:
                continue

        if not filled:
            print(f"{Colors.RED}Impossible de trouver le champ login.{Colors.RESET}")
            print(f"{Colors.DIM}URL actuelle : {self.driver.current_url}{Colors.RESET}")
            return False

        for p_by, p_sel in password_selectors:
            try:
                pass_field = self.driver.find_element(p_by, p_sel)
                pass_field.clear()
                pass_field.send_keys(password)
                break
            except Exception:
                continue

        # Submit
        submit_selectors = [
            (By.CSS_SELECTOR, "input[type='submit']"),
            (By.CSS_SELECTOR, "button[type='submit']"),
            (By.XPATH, "//input[@value='Connexion']"),
            (By.XPATH, "//button[contains(text(), 'Connexion')]"),
        ]
        for s_by, s_sel in submit_selectors:
            try:
                btn = self.driver.find_element(s_by, s_sel)
                btn.click()
                break
            except Exception:
                continue

        time.sleep(3)

        # Verify login success
        page_src = self.driver.page_source
        if "Bienvenue" in page_src or "Accueil" in page_src:
            print(f"{Colors.GREEN}Connexion reussie !{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}Login potentiellement echoue. Tentative de continuer...{Colors.RESET}")
            return True  # Try anyway

    def is_session_expired(self):
        """Check if we've been redirected to login page."""
        url = self.driver.current_url
        page = self.driver.page_source
        return ("Connexion" in page and "Bienvenue" not in page) or "login" in url.lower()

    # ── Data extraction ──

    def _navigate_to_registres(self, ref):
        url = (
            f"{self.config['base_url']}/index.php"
            f"?page=agent.GestionRegistres&ref={ref}&type=5"
        )
        self.driver.get(url)
        time.sleep(2)

        if self.is_session_expired():
            print(f"{Colors.YELLOW}Session expiree, reconnexion...{Colors.RESET}")
            self.login()
            self.driver.get(url)
            time.sleep(2)

    def _extract_consultation_info(self):
        """Extract reference, objet, date limite from the page header."""
        info = {"reference": "", "objet": "", "date_limite": ""}
        try:
            page_text = self.driver.page_source

            # Reference
            m = re.search(r"R[ée]f[ée]rence\s*:\s*</[^>]+>\s*([^<]+)", page_text)
            if m:
                info["reference"] = m.group(1).strip()

            # Objet
            m = re.search(r"Objet de la consultation\s*:\s*</[^>]+>\s*([^<]+)", page_text)
            if m:
                info["objet"] = m.group(1).strip()

            # Date limite
            m = re.search(r"Date et heure limite[^:]*:\s*</[^>]+>\s*([^<]+)", page_text)
            if m:
                info["date_limite"] = m.group(1).strip()
        except Exception:
            pass
        return info

    def _click_tab(self, tab_name):
        """Click on a tab (Retraits, Questions, Dépôts)."""
        try:
            tab_selectors = [
                f"//a[contains(text(), '{tab_name}')]",
                f"//td[contains(text(), '{tab_name}')]",
                f"//div[contains(text(), '{tab_name}')]",
                f"//span[contains(text(), '{tab_name}')]",
                f"//*[contains(@class, 'tab') and contains(text(), '{tab_name}')]",
            ]
            for sel in tab_selectors:
                elems = self.driver.find_elements(By.XPATH, sel)
                if elems:
                    elems[0].click()
                    time.sleep(1.5)
                    return True
        except Exception:
            pass
        return False

    def _extract_count_from_text(self, pattern):
        """Extract a number from page text matching a regex pattern."""
        try:
            page_text = self.driver.page_source
            m = re.search(pattern, page_text, re.IGNORECASE)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    def _extract_table_rows(self):
        """Extract rows from the current visible table."""
        rows_data = []
        try:
            tables = self.driver.find_elements(By.TAG_NAME, "table")
            for table in tables:
                rows = table.find_elements(By.TAG_NAME, "tr")
                for row in rows[1:]:  # skip header
                    cells = row.find_elements(By.TAG_NAME, "td")
                    if len(cells) >= 2:
                        row_dict = {}
                        cell_texts = [c.text.strip() for c in cells]

                        # Try to parse: N°/Date, Entreprise, Contact, Adresse, Observations
                        if cell_texts[0]:
                            row_dict["num_date"] = cell_texts[0]
                        if len(cell_texts) > 1 and cell_texts[1]:
                            row_dict["entreprise"] = cell_texts[1]
                        if len(cell_texts) > 2 and cell_texts[2]:
                            row_dict["contact"] = cell_texts[2]
                        if len(cell_texts) > 3 and cell_texts[3]:
                            row_dict["adresse"] = cell_texts[3]
                        if len(cell_texts) > 4 and cell_texts[4]:
                            row_dict["observations"] = cell_texts[4]

                        if row_dict:
                            rows_data.append(row_dict)
        except Exception:
            pass
        return rows_data

    def scrape_consultation(self, ref):
        """Scrape all tabs for a given consultation reference."""
        state = ConsultationState()

        self._navigate_to_registres(ref)

        # Extract header info
        info = self._extract_consultation_info()
        state.reference = info["reference"]
        state.objet = info["objet"]
        state.date_limite = info["date_limite"]

        # ── Onglet Retraits ──
        if self._click_tab("Retraits"):
            state.nb_retraits = self._extract_count_from_text(
                r"Nombre de retraits[^:]*:\s*(\d+)"
            )
            if state.nb_retraits == 0:
                # Try alternative pattern
                state.nb_retraits = self._extract_count_from_text(
                    r"(\d+)\s*retrait"
                )
            state.retraits = self._extract_table_rows()
            # If count wasn't found in text, use table row count
            if state.nb_retraits == 0 and state.retraits:
                state.nb_retraits = len(state.retraits)

        # ── Onglet Questions ──
        if self._click_tab("Questions"):
            state.nb_questions = self._extract_count_from_text(
                r"Nombre de questions[^:]*:\s*(\d+)"
            )
            if state.nb_questions == 0:
                state.nb_questions = self._extract_count_from_text(
                    r"(\d+)\s*question"
                )
            state.questions = self._extract_table_rows()
            if state.nb_questions == 0 and state.questions:
                state.nb_questions = len(state.questions)

        # ── Onglet Dépôts ──
        if self._click_tab("Dépôts") or self._click_tab("Depots") or self._click_tab("pôts"):
            state.nb_depots = self._extract_count_from_text(
                r"Nombre de d[ée]p[oô]ts au format [ée]lectronique\s*:\s*(\d+)"
            )
            if state.nb_depots == 0:
                state.nb_depots = self._extract_count_from_text(
                    r"d[ée]p[oô]ts[^:]*:\s*(\d+)"
                )
            state.depots = self._extract_table_rows()
            if state.nb_depots == 0 and state.depots:
                state.nb_depots = len(state.depots)

        return state

    # ── Display ──

    def _format_change(self, current, previous, label):
        if previous is None:
            return f"{current}"
        diff = current - previous
        if diff > 0:
            return f"{current}  {Colors.GREEN}(+{diff} ▲){Colors.RESET}"
        elif diff < 0:
            return f"{current}  {Colors.RED}({diff} ▼){Colors.RESET}"
        return f"{current}  {Colors.DIM}(inchange){Colors.RESET}"

    def display_state(self, ref, label, state, prev_state):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print()
        print(f"{Colors.BOLD}{Colors.CYAN}  [{now}] {label} (ref: {ref}){Colors.RESET}")
        if state.objet:
            print(f"   {state.objet}")
        if state.date_limite:
            print(f"   Date limite : {state.date_limite}")
        print(f"   {'─' * 50}")

        prev_r = prev_state.nb_retraits if prev_state else None
        prev_d = prev_state.nb_depots if prev_state else None
        prev_q = prev_state.nb_questions if prev_state else None

        print(f"   Retraits    : {self._format_change(state.nb_retraits, prev_r, 'retraits')}")
        print(f"   Depots      : {self._format_change(state.nb_depots, prev_d, 'depots')}")
        print(f"   Questions   : {self._format_change(state.nb_questions, prev_q, 'questions')}")

        # Show deposit details
        if state.depots:
            print(f"\n   {Colors.BOLD}Derniers depots :{Colors.RESET}")
            for i, dep in enumerate(state.depots, 1):
                num_date = dep.get("num_date", "?")
                entreprise = dep.get("entreprise", "-")
                is_new = prev_state and i > len(prev_state.depots) if prev_state else False
                marker = f" {Colors.GREEN}*** NOUVEAU ***{Colors.RESET}" if is_new else ""
                print(f"   #{i}  {num_date}  {entreprise}{marker}")

        # Show retrait details if there are any
        if state.retraits:
            print(f"\n   {Colors.BOLD}Derniers retraits :{Colors.RESET}")
            for i, ret in enumerate(state.retraits, 1):
                num_date = ret.get("num_date", "?")
                entreprise = ret.get("entreprise", "-")
                is_new = prev_state and i > len(prev_state.retraits) if prev_state else False
                marker = f" {Colors.GREEN}*** NOUVEAU ***{Colors.RESET}" if is_new else ""
                print(f"   #{i}  {num_date}  {entreprise}{marker}")

    def display_header(self):
        print(f"\n{'=' * 60}")
        print(f"{Colors.BOLD}  Suivi des Appels d'Offres - marchespublics.gov.ma{Colors.RESET}")
        print(f"{'=' * 60}")

    # ── Main loop ──

    def run(self):
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

        self.start_browser()
        try:
            if not self.login():
                print(f"{Colors.RED}Echec de connexion. Verifiez vos identifiants.{Colors.RESET}")
                return

            interval = self.config.get("poll_interval_seconds", 120)
            consultations = self.config.get("consultations", [])

            if not consultations:
                print(f"{Colors.RED}Aucune consultation configuree.{Colors.RESET}")
                return

            cycle = 0
            while self._running:
                cycle += 1
                self.display_header()
                print(f"{Colors.DIM}  Cycle #{cycle}{Colors.RESET}")

                for cons in consultations:
                    ref = cons["ref"]
                    label = cons.get("label", ref)

                    try:
                        state = self.scrape_consultation(ref)
                        prev = self.previous_states.get(ref)
                        self.display_state(ref, label, state, prev)
                        self.previous_states[ref] = state
                    except Exception as e:
                        print(f"\n{Colors.RED}  Erreur pour {label}: {e}{Colors.RESET}")
                        # Try to recover session
                        if self.is_session_expired():
                            self.login()

                print(f"\n{'=' * 60}")
                print(
                    f"{Colors.DIM}  Prochain rafraichissement dans {interval}s "
                    f"(Ctrl+C pour arreter){Colors.RESET}"
                )
                print(f"{'=' * 60}")

                # Sleep in small increments to respond to Ctrl+C quickly
                for _ in range(interval):
                    if not self._running:
                        break
                    time.sleep(1)

        finally:
            self.stop_browser()

    def _handle_exit(self, signum, frame):
        print(f"\n{Colors.YELLOW}Arret en cours...{Colors.RESET}")
        self._running = False


# ── CLI ───────────────────────────────────────────────────────────────────────

def load_config(args):
    """Build config from file and/or CLI arguments."""
    config = {
        "base_url": "https://www.marchespublics.gov.ma",
        "consultations": [],
        "poll_interval_seconds": 120,
        "headless": True,
    }

    # Load from file
    config_path = args.config
    if os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            file_config = json.load(f)
        config.update(file_config)

    # CLI overrides
    if args.user:
        config["username"] = args.user
    if args.password:
        config["password"] = args.password
    if args.ref:
        config["consultations"] = [
            {"ref": r.strip(), "label": r.strip()} for r in args.ref.split(",")
        ]
    if args.interval:
        config["poll_interval_seconds"] = args.interval
    if args.no_headless:
        config["headless"] = False

    # Validate
    if not config.get("username") or not config.get("password"):
        print(f"{Colors.RED}Erreur: username et password requis.{Colors.RESET}")
        print("Utilisez --user/--password ou creez un fichier config.json")
        print("  cp config.example.json config.json && nano config.json")
        sys.exit(1)

    if not config.get("consultations"):
        print(f"{Colors.RED}Erreur: au moins une consultation requise (--ref ou config.json).{Colors.RESET}")
        sys.exit(1)

    return config


def main():
    parser = argparse.ArgumentParser(
        description="Suivi en temps reel des soumissionnaires - marchespublics.gov.ma"
    )
    parser.add_argument(
        "--config", default="config.json",
        help="Chemin vers le fichier de configuration (defaut: config.json)"
    )
    parser.add_argument("--user", help="Nom d'utilisateur du portail")
    parser.add_argument("--password", help="Mot de passe du portail")
    parser.add_argument(
        "--ref",
        help="Reference(s) de consultation, separees par des virgules (ex: 979388,979400)"
    )
    parser.add_argument(
        "--interval", type=int,
        help="Intervalle de rafraichissement en secondes (defaut: 120)"
    )
    parser.add_argument(
        "--no-headless", action="store_true",
        help="Afficher le navigateur (mode non-headless)"
    )
    args = parser.parse_args()

    config = load_config(args)
    tracker = BidderTracker(config)
    tracker.run()


if __name__ == "__main__":
    main()
