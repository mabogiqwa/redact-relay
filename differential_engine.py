from __future__ import annotations

import re
import uuid
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#POPIA aware placeholders
PLACEHOLDER_TYPES = {
    "SA_ID":       "SA identity number",
    "PASSPORT":    "passport number",
    "PHONE":       "phone number",
    "EMAIL":       "email address",
    "ADDRESS":     "street address",
    "POSTCODE":    "postal code",
    "BANK_ACCT":   "bank account number",
    "DATE":        "date",
    "URL":         "URL",
    "PERSON":      "person name",
    "ORG":         "organisation name",
    "LOCATION":    "location / address",
    "VEHICLE_REG": "vehicle registration",
    "TAX_REF":     "tax reference number",
    # Healthcare domain
    "MEDICAL_ID":  "medical record number",
    "HPCSA_NO":    "health practitioner registration number",
    "HOSPITAL":    "healthcare institution",
    # Insurance / legal domain
    "POLICY_NO":   "insurance policy number",
    "CASE_NO":     "police or court case number",
    "VIN":         "vehicle identification number",
    "EMP_NO":      "employee number",
    "COMPANY_REG": "company registration number",
}

REDACTION_MODE_FILTERS = {
    "general": {
        "include_locations": False,
        "include_orgs": True,
        "include_vehicles": False,
        "include_healthcare": False,
    },
    "medical": {
        "include_locations": True,   # location can be identifying in healthcare
        "include_orgs": True,        # hospital names are sensitive
        "include_vehicles": False,
        "include_healthcare": True,
    },
    "insurance": {
        "include_locations": True,
        "include_orgs": False,       # insurer names are not PII
        "include_vehicles": True,    # VIN, reg are central to claims
        "include_healthcare": False,
    },
    "legal": {
        "include_locations": True,
        "include_orgs": True,
        "include_vehicles": False,
        "include_healthcare": False,
    },
    "financial": {
        "include_locations": False,
        "include_orgs": True,   # bank/employer names are PII in financial context
        "include_vehicles": False,
        "include_healthcare": False,
    },
}


@dataclass
class DetectedSpan:
    start: int
    end: int
    text: str
    entity_type: str    
    confidence: float = 1.0
    source: str = "regex" 


@dataclass
class RedactionResult:
    original: str
    redacted: str
    session_id: str
    spans: List[DetectedSpan]
    replacements: Dict[str, str]   # placeholder → original value
    stats: Dict[str, int]          # entity_type → count

class RedactionSession:
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self._lock = threading.Lock()
        # original_value → placeholder
        self._forward: Dict[str, str] = {}
        # placeholder → original_value
        self._reverse: Dict[str, str] = {}
        # entity_type → current counter
        self._counters: Dict[str, int] = {}

    @staticmethod
    def _normalise(value: str) -> str:
        import re as _re
        return _re.sub(r'[\s\.,;:!?"\'\-]+$', '', value.lstrip()).strip()

    def get_or_create(self, original: str, entity_type: str) -> str:
        """Return existing placeholder for this value, or mint a new one."""
        with self._lock:
            normalised = self._normalise(original)
            key = f"{entity_type}::{normalised}"
            if key in self._forward:
                return self._forward[key]
            n = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = n
            placeholder = f"[{entity_type}_{n}]"
            self._forward[key] = placeholder
            # Store the normalised form so restoration is clean
            self._reverse[placeholder] = normalised
            return placeholder

    def restore(self, text: str) -> str:
        """Replace all placeholders in text with their original values."""
        with self._lock:
            result = text
            # Sort by length descending so [PERSON_10] is replaced before [PERSON_1]
            for ph in sorted(self._reverse, key=len, reverse=True):
                result = result.replace(ph, self._reverse[ph])
            return result

    def vault_snapshot(self) -> Dict[str, str]:
        """Return a copy of the reverse mapping for audit purposes."""
        with self._lock:
            return dict(self._reverse)

    def clear(self) -> None:
        with self._lock:
            self._forward.clear()
            self._reverse.clear()
            self._counters.clear()

class RegexDetector:

    # Each entry: (entity_type, compiled_pattern, validate_fn | None)
    PATTERNS: List[Tuple[str, re.Pattern, Optional[callable]]] = []

    def __init__(self):
        self._build_patterns()

    def _luhn_valid(self, number: str) -> bool:
        digits = re.sub(r"\D", "", str(number))
        if len(digits) != 13:
            return False
        total = 0
        for i, ch in enumerate(reversed(digits)):
            n = int(ch)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _luhn_valid_spaced(self, raw: str) -> bool:
        """Strip whitespace then Luhn-check — for printed SAID format YYMMDD SSSS CC Z."""
        return self._luhn_valid(re.sub(r"\s", "", raw))

    def _dob_heuristic(self, raw: str) -> bool:
        digits = re.sub(r"\D", "", str(raw))
        if len(digits) != 13:
            return False
        try:
            mm = int(digits[2:4])
            dd = int(digits[4:6])
            yy = int(digits[0:2])
        except ValueError:
            return False
        if not (1 <= mm <= 12):
            return False
        if not (1 <= dd <= 31):
            return False
        from datetime import date
        year = (1900 + yy) if yy >= 24 else (2000 + yy)
        return 0 <= (date.today().year - year) <= 110

    def _build_patterns(self):
        _street = (
            r"St(?:reet)?|Rd|Road|Ave(?:nue)?|Dr(?:ive)?|Blvd|Boulevard"
            r"|Ln|Lane|Cres(?:cent)?|Cl(?:ose)?|Pl(?:ace)?|Way|Loop"
            r"|Laan|Weg|Straat"
        )
        self.PATTERNS = [
            ("SA_ID", re.compile(r"\b(\d{13})\b"), self._luhn_valid),

            ("SA_ID", re.compile(r"\b(\d{6}\s\d{4}\s\d{2}\s\d{1})\b"),
             self._luhn_valid_spaced),

            ("SA_ID", re.compile(r"(?<!\d)((?:\d+\s+){2,}\d+)(?!\d)"),
             lambda raw: (
                 raw.count(" ") >= 2
                 and len(re.sub(r"\s", "", raw)) == 13
                 and (self._luhn_valid_spaced(raw) or self._dob_heuristic(raw))
             )),

            ("SA_ID", re.compile(
                r"(?i)(?:id|id\s*number|id\s*no|identity|said)[:\s#]*"
                r"(\d{6}\s\d{4}\s\d{2}\s\d{1})\b"
            ), None),

            ("SA_ID", re.compile(r"(?<!\d)(\d{13})(?!\d)"),
             self._dob_heuristic),

            ("ADDRESS", re.compile(
                r"\b(\d{1,4}\s+(?:[A-Z][a-zA-Z]+\s+){1,4}"
                r"(?:" + _street + r"))\b",
                re.IGNORECASE,
            ), None),

            ("PHONE", re.compile(
                r"(?<!\d)"
                r"(\+27[\s\-]?(?:[1-8]\d)[\s\-]?\d{3}[\s\-]?\d{4}"  
                r"|27[\s\-]?(?:[1-8]\d)[\s\-]?\d{3}[\s\-]?\d{4}"     
                r"|0(?:[1-8]\d)[\s\-]?\d{3}[\s\-]?\d{4}"              
                r"|0(?:[1-8]\d)\d{7})"                                        
                r"(?!\d)"
            ), None),

            ("PASSPORT", re.compile(r"\b([A-Z]{1,2}\s?\d{7,9})\b"), None),

            ("TAX_REF", re.compile(r"(?<!\d)([1-9]\d{9})(?!\d)"), None),

            ("EMAIL", re.compile(
                r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
            ), None),

            ("BANK_ACCT", re.compile(
                r"(?i)(?:account(?:\s+(?:no|number|#|nr))?|acc\s*(?:no|#|nr)?)"
                r"\s*[:\.\s]*(\d{8,11})(?!\d)"
            ), None),

            ("BANK_ACCT", re.compile(
                r"(?i)(?:fnb|absa|nedbank|standard\s+bank|capitec|investec|"
                r"african\s+bank|bidvest|discovery\s+bank)"
                r"(?:[^\d]{1,60})(\d{8,11})(?!\d)"
            ), None),

            ("BANK_ACCT", re.compile(
                r"(?i)(?:account\s+number\s+is|account\s+no\.?\s+is)"
                r"\s+(\d{8,11})(?!\d)"
            ), None),

            ("POSTCODE", re.compile(
                r"(?i)(?:postcode|postal\s+code|poskode|zip)[\s:]*(\d{4})\b"
                r"|(?<!\d)(\d{4})(?!\d)(?=\s*,?\s*(?:South Africa|SA|Gauteng|"
                r"Western Cape|KwaZulu|Eastern Cape|Free State|Limpopo|"
                r"Mpumalanga|North West|Northern Cape))"
            ), None),

            ("POSTCODE", re.compile(
                r"(?i)(?:road|street|avenue|close|drive|lane|crescent|way|"
                r"place|boulevard|loop|rise|park|ridge|glen|estate|complex)"
                r"[^\d\n]{0,40},\s*[A-Za-z][a-z]+,?\s*(?P<pc>\d{4})(?!\d)"
            ), None),

            ("DATE", re.compile(
                r"\b(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}"      # 01/01/1990
                r"|\d{4}[\/\-\.]\d{2}[\/\-\.]\d{2}"               # 1990-01-01
                r"|(?:\d{1,2}\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|"
                r"Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
                r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
                r"(?:\s+\d{1,2},?)?\s+\d{4})\b"                   # 15 January 1990
            ), None),

            ("URL", re.compile(
                r"https?://[^\s]+"
                r"|www\.[^\s]+"
            ), None),

            ("MEDICAL_ID", re.compile(
                r"\bMRN[-\s]?\d{3,10}\b", re.IGNORECASE
            ), None),

            # HPCSA registration number — MP followed by 7 digits
            ("HPCSA_NO", re.compile(
                r"\b(MP\d{7})\b"
            ), None),

            # ── Insurance / legal identifiers ─────────────────────────────────

            # Insurance policy number — e.g. POL-2024-77821 or POL/2024/001
            ("POLICY_NO", re.compile(
                r"\bPOL[-/]\d{4}[-/]\d{3,8}\b", re.IGNORECASE
            ), None),

            # Police / court case number — e.g. CAS 214/02/2025, HR-CAS-2025-0042
            # Allows optional department prefix (HR-, LEGAL-, etc.) before the
            # CAS/CASE/CRN keyword, and also matches YYYY-NNNN date-sequence format.
            ("CASE_NO", re.compile(
                r"\b(?:[A-Z]{1,6}-)?(?:CAS|CASE|CRN|HR)[-\s]?\d{1,6}[/\-]\d{2}[/\-]\d{4}\b"
                r"|\b(?:[A-Z]{1,6}-)?(?:CAS|CASE|CRN)[-\s]\d{4}[-\s]\d{3,6}\b",
                re.IGNORECASE
            ), None),

            # VIN — 17-character alphanumeric (excludes I, O, Q)
            ("VIN", re.compile(
                r"\b([A-HJ-NPR-Z0-9]{17})\b"
            ), None),

            # Employee number — e.g. RMB-44921, EMP-00123, StaffRef-0049
            # Allows mixed-case alphabetic prefix of 2-10 chars (covers CamelCase
            # internal reference formats like StaffRef, EmpNo, HRRef).
            ("EMP_NO", re.compile(
                r"\b[A-Za-z]{2,10}-\d{3,8}\b"
            ), None),

            # SA company registration — e.g. 2023/123456/07
            ("COMPANY_REG", re.compile(
                r"\b\d{4}/\d{5,6}/\d{2}\b"
            ), None),
        ]

    def detect(self, text: str) -> List[DetectedSpan]:
        spans: List[DetectedSpan] = []
        for entity_type, pattern, validator in self.PATTERNS:
            for m in pattern.finditer(text):
                raw = next((g for g in m.groups() if g is not None), m.group(0))
                if validator and not validator(raw):
                    continue
                # Tier 4 (DOB heuristic) — lower confidence so audit reports
                # can distinguish it from Luhn-validated hits.
                is_tier4 = (validator is self._dob_heuristic)
                # If pattern uses a named group "pc" (e.g. postcode tier 2),
                # use that group's span so only the digits are redacted,
                # not the surrounding address context.
                try:
                    pg = m.group("pc")
                    span_start = m.start("pc")
                    span_end   = m.end("pc")
                    span_text  = pg
                except IndexError:
                    span_start = m.start()
                    span_end   = m.end()
                    span_text  = m.group(0)
                spans.append(DetectedSpan(
                    start=span_start,
                    end=span_end,
                    text=span_text,
                    entity_type=entity_type,
                    confidence=0.85 if is_tier4 else 1.0,
                    source="regex",
                ))
        return spans

class SpacyNERDetector:
    """
    Detects PERSON, ORG, GPE (locations) spans using spaCy.

    Model loading strategy (in order):
      1. Try the trained SA-capable model if configured
      2. Try en_core_web_sm (standard English NER)
      3. Fall back to rule-based capitalisation heuristics (no model needed)

    The heuristic fallback catches "Title Case Words" that appear in
    person-name or organisation-name contexts in the text.
    """

    # spaCy label → our entity type
    LABEL_MAP = {
        "PERSON":  "PERSON",
        "PER":     "PERSON",
        "ORG":     "ORG",
        "GPE":     "LOCATION",
        "LOC":     "LOCATION",
        "FAC":     "LOCATION",
    }

    def __init__(self, model_name: Optional[str] = None):
        self._nlp = None
        self._heuristic_only = False
        self._load_model(model_name)

    def _load_model(self, model_name: Optional[str]) -> None:
        try:
            import spacy
            candidates = []
            if model_name:
                candidates.append(model_name)
            candidates += ["en_core_web_sm", "en_core_web_md", "en_core_web_lg"]
            for name in candidates:
                try:
                    self._nlp = spacy.load(name)
                    return
                except OSError:
                    continue
            # No trained model — use blank model + sentencizer for heuristics
            from spacy.lang.en import English
            self._nlp = English()
            self._nlp.add_pipe("sentencizer")
            self._heuristic_only = True
        except ImportError:
            self._heuristic_only = True

    def _heuristic_detect(self, text: str) -> List[DetectedSpan]:
        """
        Fallback: detect person names and org names using pattern matching.

        Handles:
          - Standard Title Case sequences:   Zanele Dlamini, Thandi Nkosi
          - Honorific-prefixed names:         Mr Pieter van der Merwe, Dr Smith
          - Afrikaans/Dutch particles:        van der, van den, de, du, le, la
        Skips field labels by ignoring Title Case words followed by a colon.
        """
        COMMON_TITLE = {
            "The", "A", "An", "In", "On", "At", "To", "For", "Of", "And", "Or",
            "But", "With", "From", "By", "As", "Is", "Are", "Was", "Were", "Be",
            "I", "We", "He", "She", "They", "It", "My", "Your", "His", "Her",
            "Our", "Their", "Its",
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
            "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
            "South", "Africa", "African", "Cape", "Town", "Johannesburg",
            "Pretoria", "Durban", "Port", "Elizabeth",
            # Letter / document formatting words
            "Please", "Dear", "Re", "Formal", "Warning", "Breach", "Notice",
            "Regards", "Sincerely", "Yours", "Signed", "Date", "Subject",
            "Confidentiality", "Compliance", "Acknowledgement", "Signature",
            # Document structure / section heading words
            "Audit", "Report", "Review", "Summary", "Conclusion", "Introduction",
            "Background", "Overview", "Scope", "Objectives", "Findings", "Recommendations",
            "Appendix", "Annexure", "Section", "Chapter", "Part", "Schedule",
            "Table", "Figure", "Diagram", "Exhibit", "Attachment",
            # Common document field labels
            "Key", "Parties", "Important", "Dates", "Action", "Items", "Document",
            "Type", "Main", "Matter", "Details", "Information", "Reference",
            "Number", "Salary", "Status", "Owner", "Severity", "Finding",
            "Timestamp", "User", "System", "Address", "Event", "Method",
            "Description", "Comments", "Notes", "Remarks", "Instructions",
            # Risk / audit / compliance terms
            "Critical", "High", "Medium", "Low", "Open", "Closed", "Remediated",
            "Progress", "Under", "Management", "Response", "Draft", "Final",
            "Confidential", "Internal", "External", "Public", "Private",
            # Common SA business / legal terms
            "Pty", "Ltd", "Inc", "Corp", "Act", "Policy", "Procedure",
            "Protection", "Personal", "Privacy", "Data", "Security", "Access",
            "Control", "System", "Portal", "Database", "File", "Server",
            "Login", "Export", "Import", "Query", "Record", "Records",
            "Employee", "Customer", "Client", "Vendor", "Supplier",
            "Payroll", "Finance", "Legal", "Compliance", "Governance",
            "Division", "Department", "Committee", "Board", "Executive",
            # Job titles and professional roles — prevent false PERSON hits
            "Senior", "Junior", "Chief", "Head", "Lead", "Principal", "Associate",
            "Assistant", "Deputy", "Acting", "Executive", "Managing", "General",
            "Accountant", "Auditor", "Analyst", "Manager", "Director", "Officer",
            "Engineer", "Developer", "Architect", "Consultant", "Advisor",
            "Specialist", "Coordinator", "Administrator", "Supervisor",
            "Controller", "Treasurer", "Secretary", "Partner", "Associate",
            "Advocate", "Attorney", "Solicitor", "Counsel", "Registrar",
            "Inspector", "Investigator", "Commissioner", "Superintendent",
            "Technician", "Programmer", "Designer", "Planner", "Strategist",
            # Financial / banking terms that appear in Title Case
            "Merchant", "Investment", "Commercial", "Retail", "Corporate",
            "Savings", "Current", "Cheque", "Credit", "Debit", "Fixed",
            "Notice", "Money", "Capital", "Asset", "Equity", "Liability",
            # Property / real estate terms
            "Bond", "Mortgage", "Sectional", "Freehold", "Leasehold",
            "Erf", "Township", "Extension", "Phase", "Unit",
        }

        # Skip spans that start with a letter-formatting prefix like "Dear " or "Re: "
        SKIP_PREFIXES = ("Dear ", "Re:", "Re ", "CC:", "CC ")

        HONORIFICS = {"Mr", "Mrs", "Ms", "Miss", "Dr", "Prof", "Adv", "Advocate",
                      "Rev", "Sir", "Mx", "Mnr", "Mev"}
        PARTICLES = {"van", "der", "den", "de", "du", "le", "la", "von", "di", "d"}

        spans = []

        # Pre-process: mask salutation lines so "Dear Zanele Dlamini," is not
        # detected as a separate entity from "Zanele Dlamini" mid-paragraph.
        # We blank out the salutation prefix but preserve offsets by replacing
        # with equal-length whitespace so span positions remain valid.
        def blank_salutations(t: str) -> str:
            return re.sub(
                r'(?m)^(Dear|CC:|CC |Sincerely[,.]?|Regards[,.]?|To Whom)\s+',
                lambda m: ' ' * len(m.group(0)),
                t
            )
        clean_text = blank_salutations(text)

        particle_alt = '|'.join(re.escape(p) for p in PARTICLES)

        # Pattern 1: honorific + full name including particles
        honorific_pat = re.compile(
            r'\b((?:' + '|'.join(re.escape(h) for h in sorted(HONORIFICS, key=len, reverse=True)) + r')' +
            r'\.?\s+[A-Z][a-z]+' +
            r'(?:\s+(?:' + particle_alt + r'))*' +
            r'(?:\s+[A-Z][a-z]+)*' +
            r')\b(?!\s*:)'
        )
        for m in honorific_pat.finditer(clean_text):
            # Skip if this span is preceded by a letter-formatting prefix (e.g. "Dear ")
            prefix = text[max(0, m.start()-10):m.start()]
            if any(prefix.strip().endswith(p.rstrip()) for p in SKIP_PREFIXES):
                continue
            spans.append(DetectedSpan(
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                entity_type="PERSON",
                confidence=0.85,
                source="heuristic",
            ))

        # Pattern 2a: Hyphenated names — e.g. "Thandi-Marie", "Dlamini-Khumalo"
        # Matches one or more hyphen-joined capitalised word segments, optionally
        # followed by a space and further name words (including particles).
        hyphen_name_pat = re.compile(
            r'\b([A-Z][a-z]+-[A-Z][a-z]+' +
            r'(?:[- ][A-Z][a-z]+)*' +
            r'(?:\s+(?:' + particle_alt + r'))*' +
            r'(?:\s+[A-Z][a-z]+-?[A-Z]?[a-z]*)*' +
            r')\b(?!\s*:)'
        )
        for m in hyphen_name_pat.finditer(clean_text):
            already_covered = any(
                s.start <= m.start() and s.end >= m.end() for s in spans
            )
            if already_covered:
                continue
            prefix = text[max(0, m.start()-10):m.start()]
            if any(prefix.strip().endswith(p.rstrip()) for p in SKIP_PREFIXES):
                continue
            spans.append(DetectedSpan(
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                entity_type="PERSON",
                confidence=0.82,
                source="heuristic",
            ))

        # Pattern 2b: Particle-leading names — e.g. "van der Merwe Johannes Petrus"
        # where the name starts with a lowercase particle rather than a capital letter.
        particle_lead_pat = re.compile(
            r'\b((?:' + particle_alt + r')(?:\s+(?:' + particle_alt + r'))*\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\b(?!\s*:)'
        )
        for m in particle_lead_pat.finditer(clean_text):
            already_covered = any(
                s.start <= m.start() and s.end >= m.end() for s in spans
            )
            if already_covered:
                continue
            prefix = text[max(0, m.start()-10):m.start()]
            if any(prefix.strip().endswith(p.rstrip()) for p in SKIP_PREFIXES):
                continue
            spans.append(DetectedSpan(
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                entity_type="PERSON",
                confidence=0.80,
                source="heuristic",
            ))

        # Pattern 2c: Title Case sequences (2+ words) optionally with particles
        name_pat = re.compile(
            r'\b([A-Z][a-z]+' +
            r'(?:\s+(?:' + particle_alt + r'))*' +
            r'(?:\s+[A-Z][a-z]+){1,3})' +
            r'\b(?!\s*:)'
        )
        for m in name_pat.finditer(clean_text):
            already_covered = any(
                s.start <= m.start() and s.end >= m.end() for s in spans
            )
            if already_covered:
                continue
            # Skip if preceded by a letter-formatting prefix
            prefix = text[max(0, m.start()-10):m.start()]
            if any(prefix.strip().endswith(p.rstrip()) for p in SKIP_PREFIXES):
                continue
            words = [w for w in m.group(1).split() if w not in PARTICLES]
            if all(w in COMMON_TITLE for w in words):
                continue
            # Skip if any word is ALL CAPS (table header) or looks like a label
            if any(w.isupper() and len(w) > 2 for w in words):
                continue
            # Skip if the matched text contains pipe characters (markdown table)
            if '|' in m.group(0):
                continue
            # Skip if ALL non-particle words are in COMMON_TITLE
            real_words = [w for w in words if w not in PARTICLES and w not in COMMON_TITLE]
            if not real_words:
                continue
            # Skip venue/place names: Title Case 2-word spans where second word is
            # a known location noun (avoids "The Palms", "City Complex" etc.)
            VENUE_NOUNS = {
                "Palms", "Pines", "Gardens", "Heights", "Ridge", "View", "Park",
                "Square", "Mall", "Plaza", "Centre", "Center", "Tower", "Towers",
                "Complex", "Estate", "Village", "Court", "Manor", "Place",
                "Bay", "Beach", "Point", "Hills", "Glen", "Vale", "Crest",
            }
            if len(real_words) <= 2 and any(w in VENUE_NOUNS for w in real_words):
                continue
            entity_type = "PERSON" if len(words) <= 3 else "ORG"
            spans.append(DetectedSpan(
                start=m.start(),
                end=m.end(),
                text=m.group(0),
                entity_type=entity_type,
                confidence=0.8,
                source="heuristic",
            ))

        return spans

    def detect(self, text: str) -> List[DetectedSpan]:
        """Run NER on text. Uses spaCy model if available, else heuristics."""
        if self._heuristic_only or self._nlp is None:
            return self._heuristic_detect(text)
        doc = self._nlp(text)
        spans: List[DetectedSpan] = []
        for ent in doc.ents:
            entity_type = self.LABEL_MAP.get(ent.label_)
            if entity_type is None:
                continue
            spans.append(DetectedSpan(
                start=ent.start_char,
                end=ent.end_char,
                text=ent.text,
                entity_type=entity_type,
                confidence=0.85,
                source="spacy",
            ))
        if not spans:
            return self._heuristic_detect(text)
        return spans

# Healthcare institution suffixes — PERSON spans containing these become HOSPITAL
_HEALTHCARE_SUFFIXES = {
    "Hospital", "Clinic", "Clinique", "Medical", "Practice",
    "Surgery", "Pharmacy", "Laboratory", "Labs",
}

# Non-healthcare institution suffixes — PERSON spans become ORG
_ORG_SUFFIXES = {
    "Institute", "University", "College", "School", "Academy",
    "Bank", "Insurance", "Assurance", "Consulting", "Consultants",
    "Holdings", "Group", "Trust", "Fund", "Foundation",
    "Municipality", "Council", "Department", "Ministry",
    "Centre", "Center",
}

# Combined for backwards-compat checks elsewhere
_INSTITUTION_SUFFIXES = _HEALTHCARE_SUFFIXES | _ORG_SUFFIXES

# Left-context phrases that signal a healthcare institution follows
_INSTITUTION_LEFT_CONTEXT = {
    "registered at", "admitted to", "referred to", "treated at",
    "discharged from", "transferred to", "presented at", "consulting at",
}

# Professional registration patterns that get misclassified as PASSPORT
_PROFESSIONAL_REG = re.compile(r"^(MP|HP|PS|SW|PT|OT|DT|NR|ET|MR)\d{6,9}$")


def refine_spans(spans: List[DetectedSpan], text: str) -> List[DetectedSpan]:
    refined = []
    text_lower = text.lower()

    for span in spans:
        stype = span.entity_type
        stext = span.text.strip()

        if stype == "PASSPORT" and _PROFESSIONAL_REG.match(stext):
            span = DetectedSpan(
                start=span.start, end=span.end, text=span.text,
                entity_type="HPCSA_NO", confidence=span.confidence,
                source=span.source,
            )
            stype = "HPCSA_NO"

        if stype == "PERSON":
            words = stext.split()
            if any(w in _HEALTHCARE_SUFFIXES for w in words):
                span = DetectedSpan(
                    start=span.start, end=span.end, text=span.text,
                    entity_type="HOSPITAL", confidence=span.confidence,
                    source=span.source,
                )
                stype = "HOSPITAL"
            elif any(w in _ORG_SUFFIXES for w in words):
                span = DetectedSpan(
                    start=span.start, end=span.end, text=span.text,
                    entity_type="ORG", confidence=span.confidence,
                    source=span.source,
                )
                stype = "ORG"
            else:
                left_ctx = text_lower[max(0, span.start - 30):span.start]
                if any(phrase in left_ctx for phrase in _INSTITUTION_LEFT_CONTEXT):
                    span = DetectedSpan(
                        start=span.start, end=span.end, text=span.text,
                        entity_type="HOSPITAL", confidence=0.8,
                        source=span.source,
                    )
                    stype = "HOSPITAL"

        if stype == "PERSON":
            words = [w for w in stext.split() if w.lower() not in
                     {"van", "der", "den", "de", "du", "le", "la", "von"}]
            corp_suffixes = {"Pty", "Ltd", "Inc", "Corp", "Co", "CC", "NPC", "RF"}
            if any(w in corp_suffixes for w in words) or len(words) > 4:
                span = DetectedSpan(
                    start=span.start, end=span.end, text=span.text,
                    entity_type="ORG", confidence=span.confidence,
                    source=span.source,
                )

        refined.append(span)
    return refined




def merge_spans(spans: List[DetectedSpan]) -> List[DetectedSpan]:
    if not spans:
        return []

    # Sort by start, then by length descending
    sorted_spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    merged: List[DetectedSpan] = []
    for span in sorted_spans:
        if not merged:
            merged.append(span)
            continue
        last = merged[-1]
        if span.start < last.end:  # overlap
            # Keep the regex span; if both same source, keep the longer one
            if last.source == "regex" and span.source != "regex":
                continue  # keep last (regex wins)
            elif last.source != "regex" and span.source == "regex":
                merged[-1] = span  # replace with regex span
            else:
                # Same source — keep longer (already sorted, so keep last)
                continue
        else:
            merged.append(span)
    return merged


# ---------------------------------------------------------------------------
# 5. Main PromptRedactor
# ---------------------------------------------------------------------------

class PromptRedactor:
    def __init__(
        self,
        spacy_model: Optional[str] = None,
        min_confidence: float = 0.7,
        redact_locations: bool = False,
        redaction_mode: str = "general",
    ):
        self._regex = RegexDetector()
        self._ner = SpacyNERDetector(model_name=spacy_model)
        self._min_confidence = min_confidence
        self._redact_locations = redact_locations
        self._redaction_mode = redaction_mode
        self._mode_cfg = REDACTION_MODE_FILTERS.get(redaction_mode, REDACTION_MODE_FILTERS["general"])
        self._sessions: Dict[str, RedactionSession] = {}
        self._lock = threading.Lock()

    # -- Session management --------------------------------------------------

    def new_session(self) -> RedactionSession:
        session = RedactionSession()
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[RedactionSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def close_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    # -- Core redaction ------------------------------------------------------

    def redact(
        self,
        text: str,
        session: Optional[RedactionSession] = None,
    ) -> RedactionResult:
    
        own_session = session is None
        if own_session:
            session = RedactionSession()
            with self._lock:
                self._sessions[session.session_id] = session

        # Detect
        regex_spans = self._regex.detect(text)
        ner_spans = self._ner.detect(text)

        # Filter NER spans by confidence
        ner_spans = [s for s in ner_spans if s.confidence >= self._min_confidence]

        # Apply entity refinement (fixes PASSPORT→HPCSA_NO, PERSON→HOSPITAL, etc.)
        all_raw = refine_spans(regex_spans + ner_spans, text)

        # Apply mode-based filters
        cfg = self._mode_cfg
        filtered = []
        for s in all_raw:
            if s.entity_type == "LOCATION" and not cfg["include_locations"]:
                continue
            if s.entity_type in ("ORG", "HOSPITAL") and not cfg["include_orgs"]:
                # Always keep HOSPITAL in medical mode; already handled by include_orgs
                if s.entity_type == "ORG":
                    continue
            if s.entity_type in ("VIN", "VEHICLE_REG") and not cfg["include_vehicles"]:
                continue
            if s.entity_type in ("MEDICAL_ID", "HPCSA_NO", "HOSPITAL") and not cfg["include_healthcare"]:
                # Still redact MEDICAL_ID and HPCSA_NO in all modes — they are
                # always sensitive; only HOSPITAL display is mode-gated
                if s.entity_type == "HOSPITAL":
                    continue
            filtered.append(s)

        # Legacy redact_locations flag — override mode if explicitly set
        if not self._redact_locations:
            filtered = [s for s in filtered if s.entity_type != "LOCATION"]

        all_spans = merge_spans(filtered)

        # Build redacted text and vault in one pass (right-to-left to preserve offsets)
        replacements: Dict[str, str] = {}
        stats: Dict[str, int] = {}
        redacted = text
        for span in sorted(all_spans, key=lambda s: s.start, reverse=True):
            placeholder = session.get_or_create(span.text, span.entity_type)
            redacted = redacted[:span.start] + placeholder + redacted[span.end:]
            replacements[placeholder] = span.text
            stats[span.entity_type] = stats.get(span.entity_type, 0) + 1

        return RedactionResult(
            original=text,
            redacted=redacted,
            session_id=session.session_id,
            spans=all_spans,
            replacements=replacements,
            stats=stats,
        )

    def restore(self, llm_response: str, session_id: str) -> str:
        """
        Replace placeholders in an LLM response with original values.
        Returns the response with real names/IDs restored.
        """
        session = self.get_session(session_id)
        if session is None:
            return llm_response  # session expired or not found
        return session.restore(llm_response)

    def redact_messages(
        self,
        messages: List[Dict],
        session: Optional[RedactionSession] = None,
    ) -> Tuple[List[Dict], RedactionSession]:
        """
        Redact a full OpenAI-style messages list in place.
        Useful for multi-turn chat where each message has a "role" and "content".

        Returns (redacted_messages, session) — pass the session to restore()
        after receiving the LLM response.

        Example:
            messages = [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Review Sipho Nkosi's case, ID 9001010009081"},
            ]
            redacted_msgs, session = redactor.redact_messages(messages)
            response = openai.chat.completions.create(messages=redacted_msgs, ...)
            restored = redactor.restore(response.choices[0].message.content, session.session_id)
        """
        if session is None:
            session = self.new_session()
        redacted_messages = []
        for msg in messages:
            if msg.get("content") and isinstance(msg["content"], str):
                result = self.redact(msg["content"], session=session)
                redacted_messages.append({**msg, "content": result.redacted})
            else:
                redacted_messages.append(msg)
        return redacted_messages, session

    def audit_report(self, result: RedactionResult) -> Dict:
        """
        Generate a POPIA-compliant processing record for a redaction event.
        Suitable for your data processing register.
        """
        return {
            "session_id": result.session_id,
            "popia_basis": "data minimisation before cross-border transfer (POPIA s72)",
            "redaction_mode": self._redaction_mode,
            "entities_detected": result.stats,
            "total_spans": len(result.spans),
            "span_sources": {
                src: sum(1 for s in result.spans if s.source == src)
                for src in ("regex", "spacy", "heuristic")
            },
            "placeholders_issued": list(result.replacements.keys()),
            "original_length": len(result.original),
            "redacted_length": len(result.redacted),
        }
