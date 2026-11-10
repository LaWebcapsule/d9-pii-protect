"""Regex recognizers for Presidio (PatternRecognizer + checksum validation).

╔══════════════════════════════════════════════════════════════════════════╗
║  ADD A REGEX RECOGNIZER HERE                                               ║
║  • without checksum: add a line to SIMPLE  (ENTITY, regex, score, context) ║
║  • with checksum:    add a _Checksum(...)  in build_recognizers()          ║
║  The "context" = words that raise the score when nearby (Presidio feature).║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import re
from presidio_analyzer import PatternRecognizer, Pattern

LANG = "fr"

def luhn(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9: x -= 9
        t += x
    return len(d) > 0 and t % 10 == 0

def iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not (15 <= len(s) <= 34): return False
    s = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in s)) % 97 == 1
    except Exception:
        return False

def _ndig(s): return sum(c.isdigit() for c in s)

# French month names, used to match textual dates (matching data, not translatable).
_MOIS = "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre"

# Street types (voie), used to detect an address line even when the NER only catches the house number.
_VOIE = (r"rue|avenue|av|bd|boulevard|impasse|allée|allee|chemin|place|quai|cours|route|rte|"
         r"passage|square|voie|faubourg|fg|résidence|residence|lotissement")

# Gazetteer of the largest French communes — catches a city mentioned on its own (the NER model has a VILLE
# label but rarely predicts it). Matching data, not translatable. Extend as needed.
_CITIES = [
    "Paris", "Marseille", "Lyon", "Toulouse", "Nice", "Nantes", "Montpellier", "Strasbourg", "Bordeaux",
    "Lille", "Rennes", "Reims", "Le Havre", "Saint-Étienne", "Toulon", "Grenoble", "Dijon", "Angers",
    "Nîmes", "Villeurbanne", "Clermont-Ferrand", "Le Mans", "Aix-en-Provence", "Brest", "Tours", "Amiens",
    "Limoges", "Annecy", "Perpignan", "Besançon", "Metz", "Orléans", "Rouen", "Mulhouse", "Caen", "Nancy",
    "Argenteuil", "Montreuil", "Roubaix", "Tourcoing", "Nanterre", "Avignon", "Poitiers", "Créteil",
    "Versailles", "Pau", "Calais", "La Rochelle", "Cannes", "Antibes", "Béziers", "Colmar", "Bourges",
    "Mérignac", "Saint-Nazaire", "Valence", "Quimper", "Troyes", "Chambéry", "Lorient", "Vannes", "Bayonne",
    "Ajaccio", "Dunkerque", "Cherbourg", "Niort", "Chartres", "Angoulême", "Lorient",
]
# Match Title-case ("Paris") AND all-caps ("PARIS", common on tickets/invoices), but not lowercase (FP-prone).
_city_forms = _CITIES + [c.upper() for c in _CITIES]
_CITY_RE = r"\b(?:" + "|".join(c.replace(".", r"\.") for c in _city_forms) + r")\b"
# Presidio compiles patterns case-INSENSITIVE; force the gazetteer case-sensitive so it matches the proper
# noun "Paris" but not the lowercase common word, and doesn't fire on arbitrary capitalized words.
_CITY = r"(?-i:" + _CITY_RE + r")"
_POSTAL = r"(?:0[1-9]|[1-8]\d|9[0-5]|97|98)\d{3}"   # FR postal code, valid department prefixes only

# --- Recognizers WITHOUT checksum: (ENTITY, regex, score, [context words]) ---
# We reuse the TYPE VOCABULARY of the NER model (see ner.py LABELS) so there is a SINGLE list of
# types to know about (e.g. PII_PROTECT_SKIP=DATE covers every date). Align these names on the
# model's entity set if you switch NER models. Context words are matched in French text (kept as-is).
SIMPLE = [
    ("EMAIL",     r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0.9, ["email", "mail", "contact"]),
    ("TELEPHONE", r"(?:\+33|0)[\s.]?\d(?:[\s.]?\d\d){4}", 0.6, ["tel", "téléphone", "appeler", "joindre", "portable"]),
    ("IP",        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.6, ["ip", "serveur", "adresse"]),
    ("NUM_SECURITE_SOCIALE", r"\b[12](?:[ .]?\d){14}\b", 0.7, ["nir", "sécurité sociale", "sécu", "assuré", "sociale"]),
    ("DATE",      rf"\b\d{{1,2}}(?:er)?\s+(?:{_MOIS})(?:\s+\d{{4}})?\b", 0.6, ["né", "née", "le", "date"]),
    ("DATE",      r"\b\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}\b", 0.5, []),
    # --- Address / geography (the NER model barely predicts these despite having the labels) ---
    # Postal code ONLY when immediately followed by a known city ("75002 Paris") — avoids masking every
    # 5-digit number (order ids, amounts). Masks the whole "CP City" chunk.
    ("VILLE", rf"\b{_POSTAL}\s+{_CITY}", 0.7, []),
    # A street line: house number + street type + name (e.g. "12 rue de la Paix"). High score so the full
    # span wins over the NER's house-number-only fragment.
    ("ADRESSE", rf"(?i)\b\d{{1,4}}(?:\s?(?:bis|ter|quater))?\s+(?:{_VOIE})\b[^\n,.;:]{{0,50}}", 0.85,
        ["adresse", "habite", "domicil", "réside", "demeurant"]),
    # A city named on its own (gazetteer, case-sensitive so it doesn't fire on lowercase common words).
    ("VILLE", _CITY, 0.55, ["ville", "commune", "habite", "réside", "domicil"]),
]

class _Checksum(PatternRecognizer):
    def __init__(self, entity, regex, score, context, validator):
        self._validator = validator
        super().__init__(supported_entity=entity, supported_language=LANG,
                         patterns=[Pattern(entity.lower(), regex, score)], context=context)
    def validate_result(self, pattern_text):
        return self._validator(pattern_text)

def build_recognizers():
    recs = [PatternRecognizer(supported_entity=e, supported_language=LANG,
                              patterns=[Pattern(e.lower(), rx, sc)], context=ctx or None)
            for (e, rx, sc, ctx) in SIMPLE]
    # --- Recognizers WITH checksum ---
    recs += [
        _Checksum("SIREN", r"\b\d{3} ?\d{3} ?\d{3}\b", 0.3, ["siren", "société", "entreprise", "immatricul"],
                  lambda t: _ndig(t) == 9 and luhn(t)),
        _Checksum("SIRET", r"\b\d{3} ?\d{3} ?\d{3} ?\d{5}\b", 0.3, ["siret", "établissement", "société"],
                  lambda t: _ndig(t) == 14 and luhn(t)),
        _Checksum("IBAN_CODE", r"\b[A-Z]{2}\d{2}[0-9A-Z ]{10,34}\b", 0.3, ["iban", "virement", "compte", "bancaire"],
                  iban_ok),
        _Checksum("CREDIT_CARD", r"\b(?:\d[ -]?){13,19}\b", 0.3, ["carte", "cb", "paiement", "visa", "mastercard"],
                  lambda t: _ndig(t) not in (9, 14) and luhn(t)),
    ]
    return recs
