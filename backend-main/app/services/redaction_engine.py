"""
Presidio-based PII redaction engine.

- Custom recognizers: US_SSN, CREDIT_CARD, API_KEY, IP_ADDRESS for reliable detection.
- Post-processing: phone vs IP conflicts, overlapping-span deduplication (IP x1 not x2).
- Debug logging: entities requested, entities found, registry recognizers.
"""
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from faker import Faker
import re
import logging
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

fake = Faker()

# All entity types; order used for display only. Analysis runs all matching recognizers.
SUPPORTED_ENTITIES = [
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PERSON",
    "US_SSN",
    "API_KEY",
    "IP_ADDRESS",
    "LOCATION",
]

# Strict IPv4: each octet 0-255 (prevents phone numbers like 555.123.4567 from matching)
IPV4_PATTERN = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)


def _is_valid_ipv4(text: str) -> bool:
    """True if text is a valid IPv4 address (for context validation: do not treat as phone)."""
    if not text or len(text) > 45:
        return False
    return bool(IPV4_PATTERN.fullmatch(text.strip()))


def _looks_like_phone(text: str) -> bool:
    """True if text looks like a phone number misclassified as IP (e.g. 555.123.4567)."""
    if not text or len(text) > 20:
        return False
    text = text.strip()
    # Valid IPv4 should be treated as IP, not phone
    if _is_valid_ipv4(text):
        return False
    # North American style with dots
    if re.match(r"^\d{1,3}\.\d{3}\.\d{4}$", text):
        return True
    if re.match(r"^\d{3}\.\d{3}\.\d{4}$", text):
        return True
    if "555" in text and text.count(".") >= 2:
        return True
    return False


def _build_api_key_patterns():
    """High-specificity patterns for API keys and secrets."""
    return [
        # OpenAI / generic sk-* (min 20 chars after sk-)
        Pattern(name="openai_sk", regex=r"\bsk-[a-zA-Z0-9\-]{20,}\b", score=1.0),
        # GitHub personal access token
        Pattern(name="github_ghp", regex=r"\bghp_[a-zA-Z0-9]{36}\b", score=1.0),
        Pattern(name="github_gho", regex=r"\bgho_[a-zA-Z0-9]{36}\b", score=1.0),
        # AWS access key ID (AKIA + 16 alphanumeric)
        Pattern(name="aws_akia", regex=r"\bAKIA[0-9A-Z]{16}\b", score=1.0),
    ]


def _build_ip_address_patterns():
    """Strict IPv4 so 192.168.1.100 is IP_ADDRESS, not PHONE_NUMBER."""
    return [
        Pattern(
            name="ipv4_strict",
            regex=r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
            r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
            r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
            r"\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b",
            score=1.0,
        ),
    ]


def _build_ssn_patterns():
    """US SSN: XXX-XX-XXXX or XXXXXXXXX (9 digits)."""
    return [
        Pattern(name="ssn_dashes", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=1.0),
        Pattern(name="ssn_digits", regex=r"\b\d{9}\b", score=0.95),
    ]


def _luhn_checksum(digits: str) -> bool:
    """True if digits pass Luhn (mod 10). Use for optional strict CREDIT_CARD validation."""
    if not digits or not digits.isdigit():
        return False
    n = sum(int(d) for d in digits[-1::-2])
    n += sum((2 * int(d)) // 10 + (2 * int(d)) % 10 for d in digits[-2::-2])
    return n % 10 == 0


def _build_credit_card_patterns():
    """Credit card: XXXX-XXXX-XXXX-XXXX, with optional space or dash between groups."""
    return [
        Pattern(name="cc_dashes", regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", score=1.0),
        Pattern(name="cc_spaces", regex=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", score=0.9),
        Pattern(name="cc_digits", regex=r"\b\d{16}\b", score=0.95),
    ]


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _same_span(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start == b_start and a_end == b_end


def _resolve_phone_ip_conflicts(text: str, results: list) -> list:
    """
    Context validation: do not label valid IPs as phone; do not label phone-like strings as IP.
    - Remove PHONE_NUMBER when the span is a valid IPv4 (e.g. 192.168.1.100).
    - Remove IP_ADDRESS when the span looks like a phone (e.g. 555.123.4567).
    - When both match the same span: keep IP if valid IPv4, else keep PHONE.
    """
    filtered = []
    for r in results:
        span_text = text[r.start : r.end]

        if r.entity_type == "PHONE_NUMBER":
            # Do not treat valid IPv4 as phone
            if _is_valid_ipv4(span_text):
                continue
            filtered.append(r)
            continue

        if r.entity_type == "IP_ADDRESS":
            # Do not treat phone-like patterns as IP
            if _looks_like_phone(span_text):
                continue
            # If a PHONE_NUMBER result covers the same span and it's not valid IPv4, drop this IP
            has_phone_same_span = any(
                p.entity_type == "PHONE_NUMBER"
                and _same_span(r.start, r.end, p.start, p.end)
                and not _is_valid_ipv4(text[p.start : p.end])
                for p in results
            )
            if has_phone_same_span:
                continue
            filtered.append(r)
            continue

        filtered.append(r)
    return filtered


def _deduplicate_same_span(results: list, text: str) -> list:
    """When two results have the same span, keep one: prefer IP if valid IPv4, else first in list."""
    by_span: Dict[Tuple[int, int], List] = {}
    for r in results:
        key = (r.start, r.end)
        if key not in by_span:
            by_span[key] = []
        by_span[key].append(r)
    out = []
    for (start, end), group in by_span.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        span_text = text[start:end]
        ip_result = next((r for r in group if r.entity_type == "IP_ADDRESS"), None)
        if ip_result and _is_valid_ipv4(span_text):
            out.append(ip_result)
            continue
        phone_result = next((r for r in group if r.entity_type == "PHONE_NUMBER"), None)
        if phone_result:
            out.append(phone_result)
            continue
        out.append(group[0])
    return sorted(out, key=lambda r: r.start)


def _deduplicate_overlapping(results: list) -> list:
    """Merge overlapping results so each span is reported once (fixes IP x2 when only one exists)."""
    if not results:
        return results
    sorted_results = sorted(results, key=lambda r: (r.start, -(r.end - r.start)))
    kept: List = []
    for r in sorted_results:
        overlaps = any(_spans_overlap(r.start, r.end, k.start, k.end) for k in kept)
        if not overlaps:
            kept.append(r)
    return sorted(kept, key=lambda r: r.start)


class RedactionEngine:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

        # STEP 2: Force SSN and Credit Card detection (predefined + custom patterns)
        try:
            from presidio_analyzer.predefined_recognizers.us_ssn_recognizer import UsSsnRecognizer
            self.analyzer.registry.add_recognizer(UsSsnRecognizer())
        except Exception as e:
            logger.warning("Could not add predefined UsSsnRecognizer: %s", e)
        try:
            from presidio_analyzer.predefined_recognizers.credit_card_recognizer import CreditCardRecognizer
            self.analyzer.registry.add_recognizer(CreditCardRecognizer())
        except Exception as e:
            logger.warning("Could not add predefined CreditCardRecognizer: %s", e)

        # Custom SSN pattern with context (catches 123-45-6789 and 9 digits)
        custom_ssn = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[Pattern(name="ssn_pattern", regex=r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b", score=0.85)],
            context=["ssn", "social security", "social security number"],
            name="CustomUSSSNRecognizer",
        )
        self.analyzer.registry.add_recognizer(custom_ssn)

        # Custom Credit Card pattern (XXXX-XXXX-XXXX-XXXX and 16 digits)
        custom_cc = PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[Pattern(name="cc_pattern", regex=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", score=0.85)],
            name="CustomCreditCardRecognizer",
        )
        self.analyzer.registry.add_recognizer(custom_cc)

        # API_KEY and IP_ADDRESS custom recognizers
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="API_KEY",
                patterns=_build_api_key_patterns(),
                name="CustomApiKeyRecognizer",
            )
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="IP_ADDRESS",
                patterns=_build_ip_address_patterns(),
                name="CustomIPAddressRecognizer",
            )
        )

        # Debug: show which recognizers are active
        try:
            names = [getattr(rec, "name", rec.__class__.__name__) for rec in self.analyzer.registry.recognizers]
            logger.info("Registry recognizers: %s", names)
            print(f"Registry recognizers: {names}")
        except Exception as e:
            logger.warning("Could not list recognizers: %s", e)

    def sanitize(self, text: str, mode: str = "strict", entities: List[str] | None = None):
        """Strict, mask, or synthetic redaction with consistent entity handling."""
        if entities is None:
            entities_to_use = SUPPORTED_ENTITIES
        else:
            # Only allow supported entities; preserve order from request.
            entities_to_use = [e for e in entities if e in SUPPORTED_ENTITIES]

        logger.info("Entities requested: %s", entities_to_use)
        print(f"Entities requested: {entities_to_use}")

        results = self.analyzer.analyze(
            text=text,
            entities=entities_to_use,
            language="en",
        )

        # DEBUG: analysis results before any post-processing
        print(f"\n=== DEBUG ANALYSIS RESULTS ===")
        print(f"Entities requested: {entities_to_use}")
        print(f"Total results found: {len(results)}")
        for idx, res in enumerate(results):
            detected_text = text[res.start : res.end]
            print(f"  [{idx}] {res.entity_type} | '{detected_text}' | Span: ({res.start}, {res.end}) | Score: {getattr(res, 'score', 'N/A')}")
        try:
            print(f"Available recognizers: {[getattr(r, 'name', r.__class__.__name__) for r in self.analyzer.registry.recognizers]}")
        except Exception as e:
            print(f"Available recognizers: (error: {e})")
        print(f"=============================\n")

        # STEP 3: Deduplicate by span so same (start, end) = one result (fixes IP x2)
        seen_spans: Set[Tuple[int, int]] = set()
        unique_results = []
        for res in results:
            span = (res.start, res.end)
            if span not in seen_spans:
                unique_results.append(res)
                seen_spans.add(span)
        results = unique_results

        results = _resolve_phone_ip_conflicts(text, results)
        results = _deduplicate_same_span(results, text)
        results = _deduplicate_overlapping(results)
        detected_items = [res.entity_type for res in results]
        logger.info("Entities found (after post-process): %s", detected_items)
        print(f"Entities found (after post-process): {detected_items}")

        if mode == "strict":
            anonymized_result = self.anonymizer.anonymize(text=text, analyzer_results=results)
            return {
                "clean_text": anonymized_result.text,
                "items": detected_items,
                "synthetic_map": {},
            }
        if mode == "synthetic":
            return self._generate_synthetic_text(text, results, detected_items)
        if mode == "mask":
            return self._generate_mask_text(text, results, detected_items)
        raise ValueError(f"Unsupported mode: {mode}. Use 'strict', 'synthetic', or 'mask'")

    def _generate_synthetic_text(self, text: str, results: list, detected_items: list) -> dict:
        """Same original value => same fake value (consistency)."""
        results = sorted(results, key=lambda x: x.start, reverse=True)
        mapping = {}
        clean_text = text
        for entity in results:
            original_word = text[entity.start : entity.end]
            if original_word in mapping:
                fake_replacement = mapping[original_word]
            else:
                fake_replacement = self._get_fake_value(entity.entity_type)
                mapping[original_word] = fake_replacement
            clean_text = clean_text[: entity.start] + fake_replacement + clean_text[entity.end :]
        return {
            "clean_text": clean_text,
            "items": detected_items,
            "synthetic_map": mapping,
        }

    def _generate_mask_text(self, text: str, results: list, detected_items: list) -> dict:
        """Mask with per-entity-type counters; same span/text reuses same replacement (no double-count)."""
        results = sorted(results, key=lambda x: x.start, reverse=True)
        mapping: Dict[str, str] = {}
        counter_per_type: Dict[str, int] = {}
        clean_text = text
        for entity in results:
            original_word = text[entity.start : entity.end]
            entity_type = entity.entity_type
            if original_word in mapping:
                replacement = mapping[original_word]
            else:
                if entity_type not in counter_per_type:
                    counter_per_type[entity_type] = 1
                else:
                    counter_per_type[entity_type] += 1
                replacement = f"{entity_type} {counter_per_type[entity_type]}"
                mapping[original_word] = replacement
            clean_text = clean_text[: entity.start] + replacement + clean_text[entity.end :]
        return {
            "clean_text": clean_text,
            "items": detected_items,
            "synthetic_map": mapping,
        }

    def _get_fake_value(self, entity_type: str) -> str:
        """Consistent fake value per entity type."""
        if entity_type == "PERSON":
            return fake.name()
        if entity_type == "EMAIL_ADDRESS":
            return fake.email()
        if entity_type == "PHONE_NUMBER":
            return fake.phone_number()
        if entity_type == "CREDIT_CARD":
            return fake.credit_card_number()
        if entity_type == "US_SSN":
            return fake.ssn()
        if entity_type == "API_KEY":
            return f"sk-fake-{fake.uuid4().replace('-', '')[:44]}"
        if entity_type == "LOCATION":
            return fake.city()
        if entity_type == "IP_ADDRESS":
            return fake.ipv4()
        return f"<{entity_type}>"
