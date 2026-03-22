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

import hashlib
import urllib3

# Selenium (optional — not needed in --http-only mode)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait
    from webdriver_manager.chrome import ChromeDriverManager
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

# HTTP fallback (requests + BeautifulSoup)
try:
    import requests as http_requests
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


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

# Known public pages (accessible without authentication)
PUBLIC_PAGES = {
    "annonces": f"{BASE_URL}/index.php?page=entreprise.EntrepriseAnnonceList",
    "recherche": f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch",
    "recherche_all": f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons",
    "societes_exclues": f"{BASE_URL}/index.php?page=entreprise.EntrepriseSocietesExclues",
    "aide": f"{BASE_URL}/index.php?page=entreprise.EntrepriseAide",
    "preparer": f"{BASE_URL}/index.php?page=entreprise.EntreprisePreparerRepondre",
    "home": f"{BASE_URL}/index.php?page=entreprise.EntrepriseHome",
}

# Smart bypass strategies — alternative URL patterns to reach consultation data
# Ordered by likelihood of exposing ICE/bidder data
BYPASS_STRATEGIES = [
    # ── ICE-targeted strategies (highest priority) ──
    # 1. Agent registre page — directly request agent page without auth
    #    type=1 = Retraits, type=3 = Questions, type=5 = Dépôts
    {
        "name": "Agent Registre Retraits (type=1)",
        "url_template": BASE_URL + "/index.php?page=agent.GestionRegistres"
                        "&ref={ref}&type=1",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Agent Registre Depots (type=5)",
        "url_template": BASE_URL + "/index.php?page=agent.GestionRegistres"
                        "&ref={ref}&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 2. Entreprise registre pages — may show bidders to other registered enterprises
    {
        "name": "Entreprise Registres (ref)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseRegistres"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise Registres (refConsultation)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseRegistres"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 3. Agent registre without type — may default to showing all registres
    {
        "name": "Agent Registre (sans type)",
        "url_template": BASE_URL + "/index.php?page=agent.GestionRegistres"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 4. Agent TableauDeBord — might expose summary with bidder count
    {
        "name": "Agent TableauDeBord",
        "url_template": BASE_URL + "/index.php?page=agent.TableauDeBord"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 5. Popup observation registre — direct access to deposit entry
    #    IDs found in auth HTML: 1257061, 1257200, 1257218
    {
        "name": "Popup Observation Registre (id probe)",
        "url_template": BASE_URL + "/index.php?page=agent.popUpObservationRegistre"
                        "&id=1257200&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 6. Extrait PV — public post-ouverture, contains bidder names/ICE
    {
        "name": "Extrait PV (resultats)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseAdvancedSearch"
                        "&AvisExtraitPV&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 7. Avis Attribution — public award notice with winning ICE
    {
        "name": "Avis Attribution",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseAdvancedSearch"
                        "&AvisAttribution&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # 8. Resultats consultation
    {
        "name": "Resultats consultation",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseResultats"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Metadata strategies ──
    # 9. PopUpDetailLots — public popup showing lot details
    {
        "name": "Detail des lots (popup)",
        "url_template": BASE_URL + "/index.php?page=commun.PopUpDetailLots"
                        "&orgAccronyme={org}&refConsultation={ref}&lang=fr",
        "needs_org": True,
        "type": "search",
    },
    # 10. DCE download page
    {
        "name": "Telechargement DCE",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseDemandeTelechargementDce"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "search",
    },
    # 11. SPIP RSS feed
    {
        "name": "SPIP portail (pmmp)",
        "url_template": BASE_URL + "/pmmp/spip.php?page=backend",
        "needs_org": False,
        "type": "rss",
    },
    # ── Phase 2: Commun namespace (shared pages, possibly no auth) ──
    {
        "name": "Commun RegistreDepots",
        "url_template": BASE_URL + "/index.php?page=commun.RegistreDepots"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun RegistreRetraits",
        "url_template": BASE_URL + "/index.php?page=commun.RegistreRetraits"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun GestionRegistres",
        "url_template": BASE_URL + "/index.php?page=commun.GestionRegistres"
                        "&ref={ref}&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun ConsultationDetails",
        "url_template": BASE_URL + "/index.php?page=commun.ConsultationDetails"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun PopUpRegistre",
        "url_template": BASE_URL + "/index.php?page=commun.PopUpRegistre"
                        "&ref={ref}&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun PopUpObservationRegistre",
        "url_template": BASE_URL + "/index.php?page=commun.PopUpObservationRegistre"
                        "&id=1257200&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun ResultatsConsultation",
        "url_template": BASE_URL + "/index.php?page=commun.ResultatsConsultation"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Commun ExportRegistre XLS",
        "url_template": BASE_URL + "/index.php?page=commun.ExportRegistre"
                        "&ref={ref}&type=5&format=xls",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Phase 3: Entreprise pages with different naming patterns ──
    {
        "name": "Entreprise RegistreDepots",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseRegistreDepots"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise RegistreRetraits",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseRegistreRetraits"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise ConsultationRegistre",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseConsultationRegistre"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise AvisResultat",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseAvisResultat"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise AvisAttribution",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseAvisAttribution"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise SuiviDepot",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseSuiviDepot"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise ConsultationResultats",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseConsultationResultats"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Entreprise ListeRetraits",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseListeRetraits"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    # ── Phase 4: Agent export/download endpoints ──
    {
        "name": "Agent ExportRegistre",
        "url_template": BASE_URL + "/index.php?page=agent.ExportRegistre"
                        "&ref={ref}&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Agent ExportDepots XLS",
        "url_template": BASE_URL + "/index.php?page=agent.ExportDepots"
                        "&ref={ref}&format=xls",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Agent ConsultationDetails",
        "url_template": BASE_URL + "/index.php?page=agent.ConsultationDetails"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Agent GestionConsultation",
        "url_template": BASE_URL + "/index.php?page=agent.GestionConsultation"
                        "&ref={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Phase 5: API / REST / JSON endpoints ──
    {
        "name": "API consultation JSON",
        "url_template": BASE_URL + "/index.php?page=api.Consultation"
                        "&ref={ref}&format=json",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "API registre JSON",
        "url_template": BASE_URL + "/index.php?page=api.Registre"
                        "&ref={ref}&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "REST consultations",
        "url_template": BASE_URL + "/api/consultations/{ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "REST registre depots",
        "url_template": BASE_URL + "/api/consultations/{ref}/depots",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "WS consultation",
        "url_template": BASE_URL + "/ws/consultation/{ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Phase 6: JAL / Avis downloads ──
    {
        "name": "JAL Attribution (idAvis=1)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseDownloadAvisJAL"
                        "&refConsultation={ref}&orgAcronyme={org}&idAvis=1",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "JAL Attribution (idAvis=2)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseDownloadAvisJAL"
                        "&refConsultation={ref}&orgAcronyme={org}&idAvis=2",
        "needs_org": True,
        "type": "ice_hunt",
    },
    {
        "name": "Avis publication",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseDetailsAvis"
                        "&refConsultation={ref}&orgAcronyme={org}",
        "needs_org": True,
        "type": "ice_hunt",
    },
    # ── Phase 7: SPIP CMS / Open Data ──
    {
        "name": "SPIP API JSON",
        "url_template": BASE_URL + "/pmmp/spip.php?page=backend&format=json",
        "needs_org": False,
        "type": "search",
    },
    {
        "name": "SPIP article ref",
        "url_template": BASE_URL + "/pmmp/spip.php?action=converser&arg={ref}",
        "needs_org": False,
        "type": "search",
    },
    {
        "name": "Open Data consultations",
        "url_template": BASE_URL + "/opendata/consultations/{ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Phase 8: Observation / popup with ID brute-force range ──
    {
        "name": "Popup Observation Registre (id-1)",
        "url_template": BASE_URL + "/index.php?page=agent.popUpObservationRegistre"
                        "&id=1257061&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Popup Observation Registre (id-3)",
        "url_template": BASE_URL + "/index.php?page=agent.popUpObservationRegistre"
                        "&id=1257218&type=5",
        "needs_org": False,
        "type": "ice_hunt",
    },
    {
        "name": "Popup Observation Retrait (id-1)",
        "url_template": BASE_URL + "/index.php?page=agent.popUpObservationRegistre"
                        "&id=1257200&type=1",
        "needs_org": False,
        "type": "ice_hunt",
    },
    # ── Phase 9: Societes exclues cross-reference ──
    {
        "name": "Societes exclues (with ref)",
        "url_template": BASE_URL + "/index.php?page=entreprise.EntrepriseSocietesExclues"
                        "&refConsultation={ref}",
        "needs_org": False,
        "type": "ice_hunt",
    },
]

# Indicators that we've been denied access / redirected to login
# NOTE: "Vous n'êtes pas authentifié" and "S'identifier" appear in the nav/menu
# of the publicly accessible entreprise page — they are NOT indicators of access denial.
# The entreprise consultation detail page is publicly accessible even without login.
ACCESS_DENIED_INDICATORS = [
    "Vous n'avez pas le droit d'accéder",
    "Accès refusé",
    "Erreur d'authentification",
    "Session expirée",
]

# Known org acronyms discovered from HTML analysis
# orgAcronyme is required for entreprise.EntrepriseDetailsConsultation
KNOWN_ORG_ACRONYMS = {
    # ref -> orgAcronyme (discovered from inspect element or previous scrapes)
    "979388": "q1s",
}

# CSS selectors for data extraction on entreprise page (publicly accessible)
ENTREPRISE_SELECTORS = {
    "reference": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_reference",
    "objet": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_objet",
    "date_limite": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_dateHeureLimiteRemisePlis",
    "acheteur": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_entiteAchat",
    "annonce": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_annonce",
    "procedure": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_typeProcedure",
    "categorie": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_categoriePrincipale",
    "lots": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_nbrLots",
    "lieu_execution": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_lieuxExecutions",
    "contact": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_contactAdministratif",
    "email": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_email",
    "telephone": "ctl0_CONTENU_PAGE_idEntrepriseConsultationSummary_telephone",
}

# CSS selectors for data extraction on agent page (requires auth)
AGENT_SELECTORS = {
    "reference": "ctl0_CONTENU_PAGE_ConsultationSummary_reference",
    "objet": "ctl0_CONTENU_PAGE_ConsultationSummary_objet",
    "date_limite": "ctl0_CONTENU_PAGE_ConsultationSummary_dateFin",
    "acheteur": "ctl0_CONTENU_PAGE_ConsultationSummary_service",
    "nombre_depots": "ctl0_CONTENU_PAGE_registreDepotsElectronique_nombreResultat",
}


class PublicTracker:
    def __init__(self, refs, org=None, interval=120, headless=True, csv_path="tracker_log.csv",
                 http_only=False):
        self.refs = refs
        self.org = org
        self.interval = interval
        self.headless = headless
        self.csv_path = csv_path
        self.driver = None
        self.previous_states = {}
        self._running = True
        self.use_http = http_only
        self.session = None

    # ── HTTP session setup (fallback mode) ──

    def _init_http_session(self):
        if not HAS_REQUESTS:
            raise RuntimeError(
                "Mode HTTP requis mais 'requests' non installe.\n"
                "Installez: pip3 install requests beautifulsoup4"
            )
        self.session = http_requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "fr-FR,fr;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.use_http = True
        print(f"{Colors.CYAN}  Session HTTP initialisee (mode sans navigateur){Colors.RESET}")

    # ── Browser setup ──

    def start_browser(self, enable_network_logging=False):
        if self.use_http:
            if not self.session:
                self._init_http_session()
            return

        if not HAS_SELENIUM:
            print(f"{Colors.YELLOW}  Selenium non installe. Basculement en mode HTTP...{Colors.RESET}")
            self._init_http_session()
            return

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
            # Fix SSL errors on macOS (self-signed cert in proxy chain)
            os.environ['WDM_SSL_VERIFY'] = '0'
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=opts)
        except Exception as e1:
            try:
                self.driver = webdriver.Chrome(options=opts)
            except Exception as e2:
                if HAS_REQUESTS:
                    print(f"{Colors.YELLOW}  Chrome/ChromeDriver indisponible: {e2}{Colors.RESET}")
                    print(f"{Colors.YELLOW}  Basculement automatique en mode HTTP...{Colors.RESET}")
                    self._init_http_session()
                    return
                else:
                    print(f"\n{Colors.RED}Chrome/ChromeDriver introuvable et 'requests' non installe.{Colors.RESET}")
                    print(f"{Colors.YELLOW}Solutions:{Colors.RESET}")
                    print(f"  1. Installer Chrome: https://google.com/chrome")
                    print(f"  2. Fix SSL Mac: /Applications/Python\\ 3.x/Install\\ Certificates.command")
                    print(f"  3. Mode HTTP (sans Chrome): pip3 install requests beautifulsoup4")
                    print(f"     puis relancer avec --http-only")
                    raise

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

    # ── HTTP fallback methods ──

    def _http_get(self, url, max_retries=3):
        for attempt in range(max_retries):
            try:
                resp = self.session.get(url, timeout=30)
                return resp.text
            except Exception as e:
                if attempt < max_retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"{Colors.YELLOW}  Tentative HTTP {attempt+1}/{max_retries} echouee. "
                          f"Retry dans {wait}s...{Colors.RESET}")
                    time.sleep(wait)
                else:
                    print(f"{Colors.RED}  Echec HTTP apres {max_retries} tentatives: {e}{Colors.RESET}")
                    return None

    def _extract_header_from_html(self, html):
        """Extract header info using regex (works with raw HTML, no Selenium needed).

        Supports both entreprise page (public) and agent page (auth) HTML structures.
        Uses known element IDs for precise extraction, with regex fallback.
        """
        info = {"reference": "", "objet": "", "date_limite": "", "statut": "", "organisme": "",
                "contact": "", "email": "", "telephone": "", "lots": "", "org_acronyme": ""}
        if not html:
            return info

        def _extract_by_id(element_id):
            """Extract text content from a span/div with given ID."""
            m = re.search(
                rf'id="{re.escape(element_id)}"[^>]*>([^<]+)',
                html
            )
            return m.group(1).strip() if m else ""

        # Detect page type: entreprise (public) or agent (auth)
        is_entreprise = "EntrepriseDetailsConsultation" in html or "idEntrepriseConsultationSummary" in html
        is_agent = "GestionRegistres" in html or "ConsultationSummary_reference" in html

        if is_entreprise:
            selectors = ENTREPRISE_SELECTORS
        elif is_agent:
            selectors = AGENT_SELECTORS
        else:
            selectors = {}

        # Try ID-based extraction first (most reliable)
        if selectors:
            info["reference"] = _extract_by_id(selectors.get("reference", ""))
            info["objet"] = _extract_by_id(selectors.get("objet", ""))
            info["date_limite"] = _extract_by_id(selectors.get("date_limite", ""))
            info["organisme"] = _extract_by_id(selectors.get("acheteur", ""))

            if is_entreprise:
                info["contact"] = _extract_by_id(selectors.get("contact", ""))
                info["email"] = _extract_by_id(selectors.get("email", ""))
                info["telephone"] = _extract_by_id(selectors.get("telephone", ""))
                info["lots"] = _extract_by_id(selectors.get("lots", ""))

        # Extract orgAcronyme from form action or links
        m = re.search(r'orgAcronyme=([a-zA-Z0-9]+)', html)
        if m:
            info["org_acronyme"] = m.group(1)

        # Regex fallback for fields not found via ID
        if not info["reference"]:
            m = re.search(r"R[ée]f[ée]rence\s*:?\s*</[^>]+>\s*([^<]+)", html)
            if not m:
                m = re.search(r"R[ée]f[ée]rence\s*:?\s*([^<\n]+)", html)
            if m:
                info["reference"] = m.group(1).strip()

        if not info["objet"]:
            m = re.search(r"Objet\s*(?:de la consultation)?\s*:?\s*</[^>]+>\s*([^<]+)", html)
            if not m:
                m = re.search(r"Objet\s*:?\s*([^<\n]+)", html)
            if m:
                info["objet"] = m.group(1).strip()

        if not info["date_limite"]:
            m = re.search(r"Date\s+et\s+heure\s+limite[^:]*:\s*</[^>]+>\s*([^<]+)", html)
            if not m:
                m = re.search(r"Date\s+et\s+heure\s+limite[^:]*:\s*([^<\n]+)", html)
            if m:
                info["date_limite"] = m.group(1).strip()

        if not info["organisme"]:
            m = re.search(r"Organisme\s*:?\s*</[^>]+>\s*([^<]+)", html)
            if not m:
                m = re.search(r"Acheteur\s*(?:public)?\s*:?\s*</[^>]+>\s*([^<]+)", html)
            if m:
                info["organisme"] = m.group(1).strip()

        # Statut (agent page only)
        m = re.search(r"Statut\s*:?\s*</[^>]+>\s*([^<]+)", html)
        if not m:
            m = re.search(r"Statut\s*:?\s*([^<\n]+)", html)
        if m:
            info["statut"] = m.group(1).strip()

        # Extract ICE numbers from depot/retrait tables (agent page)
        info["ice_numbers"] = re.findall(r'ICE:\s*(\d{15})', html)

        # Extract nombre de depots (agent page)
        nombre_depots = _extract_by_id("ctl0_CONTENU_PAGE_registreDepotsElectronique_nombreResultat")
        if nombre_depots:
            info["nombre_depots"] = nombre_depots

        return info

    def _http_scrape_public(self, ref, org=None):
        """Scrape a consultation using HTTP requests (no browser)."""
        state = ConsultationState()

        # Try direct consultation page first
        url = self._build_url(ref, org)
        html = self._http_get(url)

        if not html:
            return state

        # Check if access is denied — try smart bypass strategies
        if self._is_access_denied(html):
            print(f"{Colors.YELLOW}  Page details protegee. Tentative bypass intelligent...{Colors.RESET}")
            state = self._try_bypass_strategies(ref, org)
            if state.tabs.get("_ice"):
                return state  # Found ICE!
            if state.objet or state.date_limite:
                return state
            # Last resort: search Annonces
            state = self._http_search_annonces(ref)
            return state

        # Page is accessible — extract header
        header = self._extract_header_from_html(html)
        state.reference = header.get("reference", ref)
        state.objet = header.get("objet", "")

        # Even though the page is accessible, try to find ICE via bypass strategies
        # (the entreprise page doesn't show ICE but agent pages might be open)
        if not header.get("ice_numbers"):
            print(f"{Colors.CYAN}  Page publique OK. Recherche ICE via bypass...{Colors.RESET}")
            bypass_state = self._try_bypass_strategies(ref, org or header.get("org_acronyme"))
            if bypass_state.tabs.get("_ice"):
                state.tabs["_ice"] = bypass_state.tabs["_ice"]
                print(f"{Colors.GREEN}  ICE trouves via bypass!{Colors.RESET}")

            # Try PRADO callback as last resort for ICE
            if not state.tabs.get("_ice"):
                print(f"{Colors.CYAN}  Tentative PRADO callback POST...{Colors.RESET}")
                prado_ice = self._try_prado_callback(ref, org or header.get("org_acronyme"))
                if prado_ice:
                    state.tabs["_ice"] = {"text": ", ".join(prado_ice)}
                    print(f"{Colors.GREEN}  ICE trouves via PRADO callback!{Colors.RESET}")
        state.date_limite = header.get("date_limite", "")
        state.statut = header.get("statut", "")
        state.organisme = header.get("organisme", "")

        # Save discovered orgAcronyme for future use
        discovered_org = header.get("org_acronyme", "")
        if discovered_org and str(ref) not in KNOWN_ORG_ACRONYMS:
            KNOWN_ORG_ACRONYMS[str(ref)] = discovered_org
            print(f"{Colors.GREEN}  orgAcronyme decouvert: {discovered_org}{Colors.RESET}")

        # Store extra fields from entreprise page
        if header.get("contact"):
            state.tabs["_contact"] = {"text": f"{header['contact']} | {header.get('email', '')} | {header.get('telephone', '')}"}
        if header.get("lots"):
            state.tabs["_lots"] = {"text": header["lots"]}
        if header.get("ice_numbers"):
            state.tabs["_ice"] = {"text": ", ".join(header["ice_numbers"])}
            print(f"{Colors.GREEN}  ICE trouves: {header['ice_numbers']}{Colors.RESET}")
        if header.get("nombre_depots"):
            state.tabs["_depots"] = {"text": f"Nombre depots: {header['nombre_depots']}"}

        # Extract visible text for change detection
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            full_text = soup.get_text(separator="\n", strip=True)
            state.page_hash = hashlib.md5(full_text.encode()).hexdigest()

            # Extract tables as basic tab content
            tables = soup.find_all("table")
            for table in tables:
                rows = table.find_all("tr")
                for row in rows[1:]:
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        cell_texts = [c.get_text(strip=True) for c in cells]
                        if any(cell_texts):
                            state.tabs.setdefault("_tables", {"text": "", "rows": []})
                            state.tabs["_tables"]["rows"].append(cell_texts)
        except Exception:
            state.page_hash = hashlib.md5(html.encode()).hexdigest()

        return state

    def _try_bypass_strategies(self, ref, org=None):
        """Try multiple smart strategies to access ICE/bidder data without auth."""
        state = ConsultationState()
        state.reference = str(ref)
        org = org or KNOWN_ORG_ACRONYMS.get(str(ref), "")
        found_ice = []

        for strategy in BYPASS_STRATEGIES:
            if strategy["needs_org"] and not org:
                continue

            name = strategy["name"]
            url = strategy["url_template"].format(ref=ref, org=org)
            stype = strategy["type"]

            print(f"{Colors.DIM}    Strategie: {name}...{Colors.RESET}", end=" ")

            try:
                html = self._http_get(url)
                if not html:
                    print(f"{Colors.DIM}pas de reponse{Colors.RESET}")
                    continue

                is_denied = self._is_access_denied(html)

                if stype == "ice_hunt":
                    # Primary goal: find ICE numbers in the response
                    ice_numbers = re.findall(r'ICE:\s*(\d{15})', html)
                    if ice_numbers:
                        print(f"{Colors.GREEN}*** ICE TROUVES: {ice_numbers} ***{Colors.RESET}")
                        found_ice.extend(ice_numbers)
                        # Extract full data from the page
                        header = self._extract_header_from_html(html)
                        state.objet = header.get("objet", state.objet)
                        state.date_limite = header.get("date_limite", state.date_limite)
                        state.organisme = header.get("organisme", state.organisme)
                        state.tabs["_ice"] = {"text": ", ".join(set(found_ice))}
                        if header.get("nombre_depots"):
                            state.tabs["_depots"] = {"text": f"Nombre depots: {header['nombre_depots']}"}
                        state.page_hash = hashlib.md5(html.encode()).hexdigest()
                        # Don't return yet — try more strategies to find additional ICE
                        continue

                    # No ICE found — but check if page is accessible (might have other data)
                    if not is_denied:
                        # Strip URL-encoded params to avoid false positives from
                        # login redirect pages with goto=...GestionRegistres...
                        clean_html = re.sub(r'(?:goto|redirect|url|action)=[^&"\'>\s]*', '', html, flags=re.IGNORECASE)
                        # Also strip href/action attribute values to avoid matching URLs
                        clean_html = re.sub(r'(?:href|action)="[^"]*"', '', clean_html, flags=re.IGNORECASE)
                        has_bidder_data = any(kw in clean_html.lower() for kw in [
                            "registre", "retrait", "dépôt", "depot",
                            "nombre de", "soumissionnaire", "table-results",
                        ])
                        if has_bidder_data:
                            print(f"{Colors.YELLOW}page accessible (donnees registre sans ICE){Colors.RESET}")
                            # Save page for analysis
                            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                            fname = f"bypass_{name.replace(' ', '_')}_{ref}_{ts}.html"
                            try:
                                with open(fname, "w", encoding="utf-8") as f:
                                    f.write(html)
                                print(f"    Sauvegarde: {fname}")
                            except Exception:
                                pass
                        else:
                            print(f"{Colors.DIM}accessible mais pas de donnees bidder{Colors.RESET}")
                    else:
                        print(f"{Colors.DIM}bloque{Colors.RESET}")

                elif stype == "rss":
                    if "<rss" in html.lower() or "<feed" in html.lower() or "<item" in html.lower():
                        print(f"{Colors.GREEN}FLUX RSS TROUVE!{Colors.RESET}")
                        # Check for ICE in RSS
                        ice_in_rss = re.findall(r'ICE:\s*(\d{15})', html)
                        if ice_in_rss:
                            found_ice.extend(ice_in_rss)
                            print(f"    ICE dans RSS: {ice_in_rss}")
                    else:
                        print(f"{Colors.DIM}pas RSS{Colors.RESET}")

                else:
                    # search, list type — look for ICE first, then metadata
                    ice_numbers = re.findall(r'ICE:\s*(\d{15})', html)
                    if ice_numbers:
                        print(f"{Colors.GREEN}*** ICE TROUVES: {ice_numbers} ***{Colors.RESET}")
                        found_ice.extend(ice_numbers)

                    if not is_denied and str(ref) in html:
                        print(f"{Colors.GREEN}REF TROUVEE!{Colors.RESET}")
                        header = self._extract_header_from_html(html)
                        if header.get("objet"):
                            state.objet = header.get("objet", "")
                            state.date_limite = header.get("date_limite", "")
                        state.page_hash = hashlib.md5(html.encode()).hexdigest()
                    elif not is_denied:
                        print(f"{Colors.YELLOW}accessible (ref absente){Colors.RESET}")
                    else:
                        print(f"{Colors.DIM}bloque{Colors.RESET}")

            except Exception as e:
                print(f"{Colors.DIM}erreur: {str(e)[:50]}{Colors.RESET}")

        # Summary
        if found_ice:
            unique_ice = list(set(found_ice))
            state.tabs["_ice"] = {"text": ", ".join(unique_ice)}
            print(f"\n{Colors.GREEN}  === ICE DECOUVERTS SANS AUTH: {unique_ice} ==={Colors.RESET}")
        else:
            print(f"{Colors.RED}    Aucune strategie n'a expose les ICE.{Colors.RESET}")

        return state

    def _try_prado_callback(self, ref, org=None):
        """Try PRADO callback POST to force server to render tab data without session.

        The idea: send a POST to the consultation page with PRADO_POSTBACK_TARGET
        set to one of the tab buttons. If the server doesn't validate the session
        on callbacks, it may render the tab content (including ICE data).
        """
        org = org or KNOWN_ORG_ACRONYMS.get(str(ref), "")
        url = self._build_url(ref, org)

        # First, GET the page to obtain PRADO_PAGESTATE
        html = self._http_get(url)
        if not html:
            return []

        pagestate_match = re.search(r'name="PRADO_PAGESTATE"[^>]*value="([^"]*)"', html)
        if not pagestate_match:
            return []

        pagestate = pagestate_match.group(1)
        print(f"{Colors.DIM}    PRADO callback: PAGESTATE obtenu ({len(pagestate)} chars){Colors.RESET}")

        # Tab targets to try (from agent page — may also work on entreprise page)
        callback_targets = [
            # Agent page tab targets
            ("ctl0$CONTENU_PAGE$firstTab", "Tab Retraits"),
            ("ctl0$CONTENU_PAGE$thirdTab", "Tab Depots"),
            # Refresh repeater (loads table data)
            ("ctl0$CONTENU_PAGE$registreDepotsElectronique$refreshRepeater", "Refresh Depots"),
            ("ctl0$CONTENU_PAGE$registreRetraitsElectronique$refreshRepeater", "Refresh Retraits"),
            # Export buttons — XLS/PDF might bypass UI auth check
            ("ctl0$CONTENU_PAGE$ctl18", "Export XLS"),
            ("ctl0$CONTENU_PAGE$ctl19", "Export PDF"),
            # Sort buttons — might trigger data render
            ("ctl0$CONTENU_PAGE$registreDepotsElectronique$dataListRegistre$ctl0$trierNum", "Sort by Num"),
            ("ctl0$CONTENU_PAGE$registreDepotsElectronique$dataListRegistre$ctl0$trierEntreprise", "Sort Entreprise"),
        ]

        found_ice = []

        # Try both regular POST and AJAX-style POST (X-Requested-With header)
        for use_ajax in [False, True]:
            if found_ice:
                break
            mode_label = "AJAX" if use_ajax else "POST"

            for target, label in callback_targets:
                try:
                    post_data = {
                        "PRADO_PAGESTATE": pagestate,
                        "PRADO_POSTBACK_TARGET": target,
                        "PRADO_POSTBACK_PARAMETER": "",
                    }
                    headers = {}
                    if use_ajax:
                        headers["X-Requested-With"] = "XMLHttpRequest"
                        # PRADO AJAX callback format
                        post_data["PRADO_CALLBACK_TARGET"] = target
                        post_data["PRADO_CALLBACK_PARAMETER"] = ""

                    print(f"{Colors.DIM}    {mode_label} {label}...{Colors.RESET}", end=" ")

                    resp = self.session.post(url, data=post_data, headers=headers,
                                             timeout=15, allow_redirects=True)
                    if resp.status_code == 200:
                        resp_html = resp.text
                        # Check for redirect to login in response
                        if self._is_access_denied(resp_html):
                            print(f"{Colors.DIM}redirige login{Colors.RESET}")
                            continue
                        ice_numbers = re.findall(r'ICE:\s*(\d{15})', resp_html)
                        if ice_numbers:
                            print(f"{Colors.GREEN}*** ICE: {ice_numbers} ***{Colors.RESET}")
                            found_ice.extend(ice_numbers)
                        elif len(resp_html) > 500 and any(kw in resp_html.lower() for kw in
                                ["table-results", "soumissionnaire", "entreprise"]):
                            print(f"{Colors.YELLOW}reponse avec donnees (pas d'ICE){Colors.RESET}")
                            # Save for analysis
                            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                            fname = f"prado_{label.replace(' ', '_')}_{ref}_{ts}.html"
                            try:
                                with open(fname, "w", encoding="utf-8") as f:
                                    f.write(resp_html)
                                print(f"      -> Sauvegarde: {fname}")
                            except Exception:
                                pass
                        else:
                            print(f"{Colors.DIM}pas de donnees{Colors.RESET}")
                    else:
                        print(f"{Colors.DIM}{resp.status_code}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.DIM}erreur: {str(e)[:40]}{Colors.RESET}")

        # Try PRADO callback on the AGENT registre URL directly (with entreprise PAGESTATE)
        if not found_ice:
            agent_urls = [
                (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type=5", "Agent Depots direct"),
                (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type=1", "Agent Retraits direct"),
            ]
            for agent_url, label in agent_urls:
                try:
                    print(f"{Colors.DIM}    POST crosspage {label}...{Colors.RESET}", end=" ")
                    post_data = {
                        "PRADO_PAGESTATE": pagestate,
                        "PRADO_POSTBACK_TARGET": "ctl0$CONTENU_PAGE$thirdTab",
                        "PRADO_POSTBACK_PARAMETER": "",
                    }
                    resp = self.session.post(agent_url, data=post_data, timeout=15,
                                             allow_redirects=True)
                    if resp.status_code == 200 and not self._is_access_denied(resp.text):
                        ice_numbers = re.findall(r'ICE:\s*(\d{15})', resp.text)
                        if ice_numbers:
                            print(f"{Colors.GREEN}*** ICE: {ice_numbers} ***{Colors.RESET}")
                            found_ice.extend(ice_numbers)
                        else:
                            print(f"{Colors.DIM}accessible sans ICE{Colors.RESET}")
                    else:
                        print(f"{Colors.DIM}bloque{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.DIM}erreur: {str(e)[:40]}{Colors.RESET}")

        return list(set(found_ice))

    def _http_search_annonces(self, ref):
        """Search for a consultation in the public Annonces page."""
        state = ConsultationState()
        state.reference = ref

        # Try multiple public page patterns for the Annonces/search
        search_urls = [
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1",
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch",
            PUBLIC_PAGES["annonces"],
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseConsultationList",
            # Direct search with reference parameter
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&refConsultation={ref}",
        ]

        for url in search_urls:
            html = self._http_get(url)
            if not html or self._is_access_denied(html):
                continue

            # Check if the reference appears on this page
            if str(ref) in html:
                print(f"{Colors.GREEN}  Ref {ref} trouvee sur: {url.split('page=')[1][:50]}{Colors.RESET}")
                state = self._extract_from_listing(html, ref)
                state.page_hash = hashlib.md5(html.encode()).hexdigest()
                return state

        print(f"{Colors.YELLOW}  Ref {ref} non trouvee dans les pages publiques.{Colors.RESET}")
        # Still hash the last page we got for change detection
        state.objet = "(acces protege - consultation non visible publiquement)"
        return state

    def _extract_from_listing(self, html, ref):
        """Extract consultation info from a listing/search results page."""
        state = ConsultationState()
        state.reference = str(ref)

        try:
            soup = BeautifulSoup(html, "html.parser")

            # Find the row containing the reference
            ref_str = str(ref)
            # Look in table rows
            for tr in soup.find_all("tr"):
                cells = tr.find_all("td")
                row_text = tr.get_text()
                if ref_str not in row_text:
                    continue

                cell_texts = [c.get_text(strip=True) for c in cells]
                # Try to extract structured data from the row
                for i, text in enumerate(cell_texts):
                    if ref_str in text:
                        state.reference = text
                    # Heuristic: date patterns
                    elif re.search(r"\d{2}/\d{2}/\d{4}", text):
                        if not state.date_limite:
                            state.date_limite = text
                    # Long text is likely the object
                    elif len(text) > 30 and not state.objet:
                        state.objet = text

                # Store full row for monitoring
                if cell_texts:
                    state.tabs["listing"] = {"text": " | ".join(cell_texts), "rows": [cell_texts]}
                break

            # Also look in divs/spans that might contain the info
            if not state.objet:
                for el in soup.find_all(string=re.compile(ref_str)):
                    parent = el.find_parent(["tr", "div", "li"])
                    if parent:
                        full_text = parent.get_text(separator=" ", strip=True)
                        if len(full_text) > len(ref_str) + 10:
                            state.objet = full_text[:200]
                            break

        except Exception as e:
            print(f"{Colors.DIM}  Erreur extraction listing: {e}{Colors.RESET}")

        return state

    # ── URL construction ──

    def _build_url(self, ref, org=None):
        # Auto-discover orgAcronyme from known mapping
        if not org:
            org = KNOWN_ORG_ACRONYMS.get(str(ref))
        url = f"{BASE_URL}/index.php?page=entreprise.EntrepriseDetailsConsultation&refConsultation={ref}"
        if org:
            url += f"&orgAcronyme={org}"
        return url

    def _is_access_denied(self, html):
        """Check if page shows actual access denial (not just unauthenticated nav bar).

        IMPORTANT: The entreprise page shows 'Vous n'êtes pas authentifié' in the
        navigation bar and 'S'identifier' in the left menu, but the page content IS
        fully served with consultation details. These are NOT access denial indicators.

        True access denial shows 'Accès refusé' or redirects to a login-only page
        without any consultation content.
        """
        if not html:
            return False
        text = html.lower() if len(html) < 50000 else html[:50000].lower()

        # Agent login redirect: form action contains agent.AgentHome with goto param
        # This is a definitive redirect — the page is a login form, not data
        if 'agent.agenthome' in text and 'goto=' in text:
            return True

        # Check for true access denial
        has_denial = any(ind.lower() in text for ind in ACCESS_DENIED_INDICATORS)
        if not has_denial:
            return False

        # Even with denial indicators, if we can see consultation data, page is accessible
        has_content = any(marker in text for marker in [
            "objet de la consultation",
            "date et heure limite",
            "référence",
            "recap-consultation",
            "acheteur public",
            "table-results",
        ])
        return not has_content

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
                # Check for access denied
                if self._is_access_denied(self.driver.page_source):
                    print(f"{Colors.RED}  ACCES REFUSE: Cette page necessite une authentification.{Colors.RESET}")
                    return False
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
            error_indicators = ACCESS_DENIED_INDICATORS + [
                "Erreur", "403", "Page introuvable",
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

    def _deep_scan_brute_force_ids(self, ref, org=None):
        """Brute-force observation popup IDs around known deposit IDs.

        The agent page reveals deposit IDs (e.g., 1257061, 1257200, 1257218).
        These IDs are sequential and predictable. The popup pages might not
        require authentication since they're lightweight detail views.
        """
        org = org or KNOWN_ORG_ACRONYMS.get(str(ref), "")
        found_ice = []

        # Known IDs from the authenticated page for ref 979388
        # We scan a range around them + try a wider range
        known_ids = [1257061, 1257200, 1257218]
        min_id = min(known_ids) - 50
        max_id = max(known_ids) + 50

        print(f"\n{Colors.CYAN}  Brute-force IDs popup: {min_id} -> {max_id}{Colors.RESET}")

        popup_pages = [
            "agent.popUpObservationRegistre",
            "commun.PopUpObservationRegistre",
            "commun.PopUpDetailDepot",
            "commun.PopUpDetailRetrait",
            "agent.popUpDetailDepot",
        ]

        for page_name in popup_pages:
            print(f"\n{Colors.DIM}    Page: {page_name}{Colors.RESET}")
            accessible_count = 0
            blocked_count = 0

            for test_id in range(min_id, max_id + 1):
                for type_val in [5, 1]:  # 5=Dépôts, 1=Retraits
                    url = f"{BASE_URL}/index.php?page={page_name}&id={test_id}&type={type_val}"
                    try:
                        html = self._http_get(url)
                        if not html:
                            continue
                        if self._is_access_denied(html):
                            blocked_count += 1
                            if blocked_count >= 3:
                                break  # This page requires auth, skip it
                            continue

                        # Check for ICE
                        ice_numbers = re.findall(r'ICE:\s*(\d{15})', html)
                        if ice_numbers:
                            print(f"{Colors.GREEN}    ID {test_id} type={type_val}: ICE = {ice_numbers}{Colors.RESET}")
                            found_ice.extend(ice_numbers)
                        elif len(html) > 200:
                            accessible_count += 1
                            if accessible_count <= 3:  # Log first few
                                print(f"{Colors.YELLOW}    ID {test_id}: accessible ({len(html)} chars){Colors.RESET}")
                                # Save for analysis
                                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                                fname = f"popup_{page_name}_{test_id}_{ts}.html"
                                try:
                                    with open(fname, "w", encoding="utf-8") as f:
                                        f.write(html)
                                except Exception:
                                    pass
                    except Exception:
                        continue

                if blocked_count >= 3:
                    print(f"{Colors.DIM}      -> page protegee, skip{Colors.RESET}")
                    break  # Skip this page_name entirely

            if accessible_count > 0:
                print(f"      -> {accessible_count} pages accessibles")

        return list(set(found_ice))

    def _deep_scan_export_direct(self, ref, org=None):
        """Try to hit export endpoints directly with various HTTP methods."""
        org = org or KNOWN_ORG_ACRONYMS.get(str(ref), "")
        found_ice = []

        # Direct export URL patterns that might bypass UI auth
        export_urls = [
            # XLS/PDF export via agent page action
            (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type=5&action=export&format=xls", "Agent XLS export"),
            (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type=5&action=export&format=pdf", "Agent PDF export"),
            (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type=1&action=export&format=xls", "Agent Retraits XLS"),
            # Common export patterns
            (f"{BASE_URL}/export/registre/{ref}/xls", "REST export XLS"),
            (f"{BASE_URL}/export/registre/{ref}/pdf", "REST export PDF"),
            (f"{BASE_URL}/index.php?page=agent.ExportXLS&ref={ref}", "ExportXLS page"),
            (f"{BASE_URL}/index.php?page=agent.ExportPDF&ref={ref}", "ExportPDF page"),
            (f"{BASE_URL}/index.php?page=commun.ExportRegistreXLS&ref={ref}&type=5", "Commun ExportXLS"),
            # Download handler
            (f"{BASE_URL}/index.php?page=commun.Download&type=registre&ref={ref}&format=xls", "Commun Download"),
        ]

        print(f"\n{Colors.CYAN}  Tentative exports directs...{Colors.RESET}")
        for url, label in export_urls:
            try:
                print(f"{Colors.DIM}    {label}...{Colors.RESET}", end=" ")
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "")

                # Check if we got a file download
                if "application/" in content_type and "html" not in content_type:
                    print(f"{Colors.GREEN}FICHIER RECU ({content_type})!{Colors.RESET}")
                    ext = "xls" if "xls" in content_type or "spreadsheet" in content_type else "pdf"
                    fname = f"export_{label.replace(' ', '_')}_{ref}.{ext}"
                    with open(fname, "wb") as f:
                        f.write(resp.content)
                    print(f"      -> Sauvegarde: {fname}")
                    # Try to find ICE in binary content
                    try:
                        text = resp.content.decode("utf-8", errors="ignore")
                        ice_numbers = re.findall(r'ICE:\s*(\d{15})', text)
                        if ice_numbers:
                            found_ice.extend(ice_numbers)
                            print(f"{Colors.GREEN}      ICE dans export: {ice_numbers}{Colors.RESET}")
                    except Exception:
                        pass
                elif resp.status_code == 200 and not self._is_access_denied(resp.text):
                    ice_numbers = re.findall(r'ICE:\s*(\d{15})', resp.text)
                    if ice_numbers:
                        print(f"{Colors.GREEN}ICE: {ice_numbers}{Colors.RESET}")
                        found_ice.extend(ice_numbers)
                    elif len(resp.text) > 500:
                        print(f"{Colors.YELLOW}reponse ({len(resp.text)} chars){Colors.RESET}")
                    else:
                        print(f"{Colors.DIM}vide{Colors.RESET}")
                else:
                    print(f"{Colors.DIM}bloque/erreur ({resp.status_code}){Colors.RESET}")
            except Exception as e:
                print(f"{Colors.DIM}erreur: {str(e)[:40]}{Colors.RESET}")

        return list(set(found_ice))

    def _deep_scan_other_consultations(self, ref, org=None):
        """Search the public search page for this consultation's resultat/attribution.

        By law (Décret 2-12-349, Art. 168), award results must be published publicly.
        After attribution, ICE of the winning bidder is visible in the public notice.
        """
        org = org or KNOWN_ORG_ACRONYMS.get(str(ref), "")
        found_ice = []

        # Try the public search page to find avis d'attribution for this consultation
        search_urls = [
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1&typeAvis=6",  # Résultats
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1&typeAvis=3",  # Attribution
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1&typeAvis=4",  # Rectificatif
            f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1&typeAvis=5",  # Annulation
        ]

        print(f"\n{Colors.CYAN}  Recherche avis publics (attribution/resultats)...{Colors.RESET}")
        for url in search_urls:
            try:
                html = self._http_get(url)
                if not html:
                    continue
                # Search for ref in results
                if str(ref) in html:
                    print(f"{Colors.GREEN}  Ref {ref} trouvee dans avis publics!{Colors.RESET}")
                    ice_numbers = re.findall(r'ICE:\s*(\d{15})', html)
                    if ice_numbers:
                        found_ice.extend(ice_numbers)
                        print(f"{Colors.GREEN}  ICE dans avis: {ice_numbers}{Colors.RESET}")
                    else:
                        # Extract links to detail pages
                        links = re.findall(r'href="([^"]*refConsultation=' + str(ref) + r'[^"]*)"', html)
                        if links:
                            for link in links[:5]:
                                detail_url = BASE_URL + "/" + link.replace("&amp;", "&") if not link.startswith("http") else link
                                detail_html = self._http_get(detail_url)
                                if detail_html:
                                    ice_in_detail = re.findall(r'ICE:\s*(\d{15})', detail_html)
                                    if ice_in_detail:
                                        found_ice.extend(ice_in_detail)
                                        print(f"{Colors.GREEN}  ICE dans detail: {ice_in_detail}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.DIM}  erreur: {str(e)[:40]}{Colors.RESET}")

        return list(set(found_ice))

    def run_deep_scan(self):
        """Run aggressive deep scan: brute-force IDs, export endpoints, public results."""
        ref = self.refs[0]
        org = self.org

        if not self.session:
            self.use_http = True
            self._init_http_session()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  DEEP SCAN - Recherche agressive ICE{Colors.RESET}")
        print(f"{Colors.BOLD}  Consultation: {ref}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")

        all_ice = []

        # Phase 1: Expanded bypass strategies (now with 40+ endpoints)
        print(f"{Colors.CYAN}[1/5] Strategies de bypass etendues ({len(BYPASS_STRATEGIES)} endpoints)...{Colors.RESET}")
        bypass_state = self._try_bypass_strategies(ref, org)
        if bypass_state.tabs.get("_ice"):
            ice_text = bypass_state.tabs["_ice"]["text"]
            all_ice.extend(ice_text.split(", "))
            print(f"{Colors.GREEN}  Phase 1: ICE trouves = {ice_text}{Colors.RESET}")

        # Phase 2: PRADO callback attacks (POST + AJAX + cross-page + export)
        print(f"\n{Colors.CYAN}[2/5] Attaques PRADO callback (POST/AJAX/export)...{Colors.RESET}")
        prado_ice = self._try_prado_callback(ref, org)
        if prado_ice:
            all_ice.extend(prado_ice)
            print(f"{Colors.GREEN}  Phase 2: ICE trouves = {prado_ice}{Colors.RESET}")

        # Phase 3: Direct export endpoints
        print(f"\n{Colors.CYAN}[3/5] Exports directs (XLS/PDF/REST)...{Colors.RESET}")
        export_ice = self._deep_scan_export_direct(ref, org)
        if export_ice:
            all_ice.extend(export_ice)
            print(f"{Colors.GREEN}  Phase 3: ICE trouves = {export_ice}{Colors.RESET}")

        # Phase 4: Brute-force popup IDs
        print(f"\n{Colors.CYAN}[4/5] Brute-force IDs popup (range autour des IDs connus)...{Colors.RESET}")
        bf_ice = self._deep_scan_brute_force_ids(ref, org)
        if bf_ice:
            all_ice.extend(bf_ice)
            print(f"{Colors.GREEN}  Phase 4: ICE trouves = {bf_ice}{Colors.RESET}")

        # Phase 5: Search public results/attribution notices
        print(f"\n{Colors.CYAN}[5/5] Recherche avis publics (attribution/resultats)...{Colors.RESET}")
        pub_ice = self._deep_scan_other_consultations(ref, org)
        if pub_ice:
            all_ice.extend(pub_ice)
            print(f"{Colors.GREEN}  Phase 5: ICE trouves = {pub_ice}{Colors.RESET}")

        # Final summary
        unique_ice = list(set(all_ice))
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        if unique_ice:
            print(f"{Colors.GREEN}{Colors.BOLD}  RESULTAT: {len(unique_ice)} ICE TROUVES SANS AUTH!{Colors.RESET}")
            for ice in unique_ice:
                print(f"{Colors.GREEN}    - ICE:{ice}{Colors.RESET}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}  RESULTAT: Aucun ICE trouve.{Colors.RESET}")
            print(f"{Colors.YELLOW}  Toutes les strategies ont ete epuisees ({len(BYPASS_STRATEGIES)} endpoints +")
            print(f"  PRADO callbacks + exports + brute-force IDs + avis publics).{Colors.RESET}")
            print(f"\n{Colors.YELLOW}  Pistes restantes:{Colors.RESET}")
            print(f"  1. Attendre apres date limite ({bypass_state.date_limite or '?'}) pour avis d'attribution")
            print(f"  2. Creer un compte entreprise (gratuit) -> registre retraits DCE visible")
            print(f"  3. Utiliser vos identifiants agent avec --login")
        print(f"{'=' * 60}\n")

    def run_discovery(self):
        if self.use_http:
            print(f"\n{Colors.RED}Le mode Discovery necessite Chrome/Selenium (clics onglets + CDP).{Colors.RESET}")
            print(f"{Colors.YELLOW}Utilisez le mode Monitor avec --http-only pour la surveillance HTTP.{Colors.RESET}")
            print(f"{Colors.YELLOW}Ou installez Chrome pour le mode Discovery.{Colors.RESET}")
            return

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
            print(f"{Colors.CYAN}[1/6] Chargement de la page consultation...{Colors.RESET}")
            url = self._build_url(ref, org)
            page_loaded = self._load_page(url)

            if not page_loaded:
                findings.append("=== PAGE CONSULTATION: ACCES REFUSE ===")
                findings.append(f"URL: {url}")
                findings.append("La page details necessite une authentification entreprise.")
                findings.append("Exploration des pages publiques alternatives...\n")
                print(f"{Colors.YELLOW}  Page details protegee. Exploration des alternatives...{Colors.RESET}")
            else:
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
            if page_loaded:
                print(f"\n{Colors.CYAN}[2/6] Exploration des onglets...{Colors.RESET}")
            else:
                print(f"\n{Colors.CYAN}[2/6] Onglets non disponibles (acces refuse).{Colors.RESET}")
            findings.append("=== CONTENU DES ONGLETS ===")

            for tab in (TAB_NAMES if page_loaded else []):
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

            # ── Phase 3: Probe public + agent URLs without auth ──
            print(f"\n{Colors.CYAN}[3/6] Sondage des pages publiques et URLs agent...{Colors.RESET}")
            findings.append("=== SONDAGE URLs (SANS AUTH) ===")

            # Public pages visible in sidebar (no auth)
            probe_urls = [
                (PUBLIC_PAGES["annonces"], "Annonces (liste publique)"),
                (PUBLIC_PAGES["recherche"], "Recherche avancee"),
                (PUBLIC_PAGES["societes_exclues"], "Societes exclues"),
                (PUBLIC_PAGES["aide"], "Aide"),
                (PUBLIC_PAGES["preparer"], "Se preparer a repondre"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseAdvancedSearch&AllCons=1",
                 "Recherche avancee (AllCons)"),
                (f"{BASE_URL}/index.php?page=entreprise.EntrepriseConsultationList", "Liste consultations"),
            ]
            # Also try the detail page (now requires auth, but let's confirm)
            probe_urls.append(
                (self._build_url(ref, org), "Details consultation (auth?)")
            )
            # Agent pages
            probe_urls.append(
                (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}", "GestionRegistres (sans type)")
            )
            for t in range(1, 6):
                probe_urls.append(
                    (f"{BASE_URL}/index.php?page=agent.GestionRegistres&ref={ref}&type={t}",
                     f"GestionRegistres type={t}")
                )
            # Other entreprise endpoints
            probe_urls.extend([
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

            # ── Phase 3b: Smart bypass strategies via Selenium ──
            print(f"\n{Colors.CYAN}[3b/6] Strategies de bypass intelligent...{Colors.RESET}")
            findings.append("\n=== STRATEGIES DE BYPASS ===")

            for strategy in BYPASS_STRATEGIES:
                if strategy["needs_org"] and not org:
                    continue

                name = strategy["name"]
                bypass_url = strategy["url_template"].format(ref=ref, org=org or "")
                print(f"  {name}...", end=" ")

                try:
                    self.driver.get(bypass_url)
                    time.sleep(3)
                    bypass_page = self.driver.page_source
                    bypass_text = self.driver.find_element(By.TAG_NAME, "body").text[:1500]
                    is_denied = self._is_access_denied(bypass_page)
                    has_ref = str(ref) in bypass_text or str(ref) in bypass_page

                    findings.append(f"\n--- {name} ---")
                    findings.append(f"  URL: {bypass_url[:120]}")
                    findings.append(f"  Acces refuse: {is_denied}")
                    findings.append(f"  Ref presente: {has_ref}")

                    if not is_denied and has_ref:
                        print(f"{Colors.GREEN}DONNEES ACCESSIBLES!{Colors.RESET}")
                        findings.append(f"  *** BYPASS REUSSI — DONNEES ACCESSIBLES ***")
                        findings.append(f"  Apercu: {bypass_text[:300]}")
                        # Try to extract data
                        header = self._extract_header()
                        if header.get("reference") or header.get("objet"):
                            findings.append(f"  Reference: {header.get('reference', 'N/A')}")
                            findings.append(f"  Objet: {header.get('objet', 'N/A')}")
                            findings.append(f"  Date limite: {header.get('date_limite', 'N/A')}")
                    elif not is_denied:
                        print(f"{Colors.YELLOW}accessible (ref absente){Colors.RESET}")
                        findings.append(f"  Page accessible mais ref non trouvee")
                        findings.append(f"  Apercu: {bypass_text[:200]}")
                    else:
                        print(f"{Colors.DIM}bloque{Colors.RESET}")
                        findings.append(f"  Acces refuse")
                except Exception as e:
                    print(f"{Colors.DIM}erreur: {str(e)[:50]}{Colors.RESET}")
                    findings.append(f"  Erreur: {e}")

                time.sleep(1)

            findings.append("")

            # ── Phase 4: Analyze PRADO callbacks ──
            print(f"\n{Colors.CYAN}[4/6] Analyse des callbacks PRADO...{Colors.RESET}")
            findings.append("=== ANALYSE PRADO ===")

            # Load a page with PRADO state (use consultation page or first accessible public page)
            if page_loaded:
                self._load_page(url)
            else:
                # Try to load any public page for PRADO analysis
                for pname, purl in PUBLIC_PAGES.items():
                    try:
                        self.driver.get(purl)
                        time.sleep(3)
                        if not self._is_access_denied(self.driver.page_source):
                            print(f"  Analyse PRADO sur page '{pname}'")
                            break
                    except Exception:
                        continue
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
            print(f"\n{Colors.CYAN}[5/6] Sauvegarde du code source pour inspection...{Colors.RESET}")
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

            # ── Phase 6: Summary ──
            print(f"\n{Colors.CYAN}[6/6] Resume:{Colors.RESET}")
            accessible_pages = [f for f in findings if "Accessible: True" in f]
            data_urls = [f for f in findings if "DONNEES TROUVEES" in f]

            if not page_loaded:
                print(f"  {Colors.RED}Page details consultation: ACCES REFUSE (auth entreprise requise){Colors.RESET}")

            if accessible_pages:
                print(f"  {Colors.GREEN}{len(accessible_pages)} page(s) accessible(s) sans auth{Colors.RESET}")
            if data_urls:
                print(f"  {Colors.GREEN}{len(data_urls)} endpoint(s) avec donnees interessantes!{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}Aucun endpoint avec donnees bidder trouve sans auth.{Colors.RESET}")
                print(f"  Les donnees de retraits/depots sont protegees par l'authentification.")
                print(f"  {Colors.CYAN}Conseil: Utilisez --http-only pour surveiller les pages publiques{Colors.RESET}")
                print(f"  {Colors.CYAN}  (Annonces, recherche) ou connectez-vous en tant qu'entreprise.{Colors.RESET}")

        finally:
            self.stop_browser()

    # ── Monitor mode: scraping ──

    def scrape_public(self, ref, org=None):
        if self.use_http:
            return self._http_scrape_public(ref, org)

        state = ConsultationState()

        url = self._build_url(ref, org)
        if not self._load_page(url):
            # Page requires auth — try Annonces page via Selenium
            print(f"{Colors.YELLOW}  Tentative via page Annonces...{Colors.RESET}")
            for page_name, page_url in PUBLIC_PAGES.items():
                try:
                    self.driver.get(page_url)
                    time.sleep(3)
                    page_text = self.driver.find_element(By.TAG_NAME, "body").text
                    if str(ref) in page_text or str(ref) in self.driver.page_source:
                        print(f"{Colors.GREEN}  Ref trouvee sur page '{page_name}'{Colors.RESET}")
                        state.reference = str(ref)
                        state.objet = f"(visible sur page {page_name})"
                        state.page_hash = str(hash(page_text))
                        return state
                except Exception:
                    continue
            state.reference = str(ref)
            state.objet = "(acces protege - authentification requise)"
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

        mode_label = "HTTP (sans navigateur)" if self.use_http else f"Selenium (headless={self.headless})"
        print(f"\n{Colors.BOLD}Demarrage du monitoring anonyme...{Colors.RESET}")
        print(f"  Consultations: {', '.join(self.refs)}")
        print(f"  Intervalle: {self.interval}s")
        print(f"  CSV: {self.csv_path}")
        print(f"  Mode: {mode_label}\n")

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
    parser.add_argument(
        "--http-only", action="store_true",
        help="Mode HTTP direct (sans Chrome/Selenium). Fonctionne partout, mais pas de clics onglets."
    )
    parser.add_argument(
        "--deep-scan", action="store_true",
        help="Scan agressif: brute-force IDs popup, export PRADO, enumeration massive endpoints"
    )
    args = parser.parse_args()

    refs = [r.strip() for r in args.ref.split(",")]
    headless = not args.no_headless

    if args.http_only and not HAS_REQUESTS:
        print(f"Erreur: --http-only necessite 'requests' et 'beautifulsoup4'.")
        print(f"Installez: pip3 install requests beautifulsoup4")
        sys.exit(1)

    tracker = PublicTracker(
        refs=refs,
        org=args.org,
        interval=args.interval,
        headless=headless,
        csv_path=args.csv_log,
        http_only=args.http_only,
    )

    if args.deep_scan:
        tracker.run_deep_scan()
    elif args.discover:
        tracker.run_discovery()
    else:
        tracker.run_monitor()


if __name__ == "__main__":
    main()
