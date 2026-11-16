import threading
import logging
from pathlib import Path

logger = logging.getLogger("etd.cascade")

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from peft import PeftModel
    HAS_ML_DEPS = True
except ImportError:
    HAS_ML_DEPS = False

BASE_MODEL_NAME = "answerdotai/ModernBERT-base"
# The adapters answer one question: is this message an instance of the threat
# category. They used to carry a five-level severity head, but two of those
# levels were not learnable from the text — Safe vs Low scored 0.476 and High
# vs Critical 0.503 on held-out templates, both at or below chance — so the
# extra classes contributed noise to the confidence the cascade acts on.
# Severity now comes from Tier 0's infrastructure score, which is measurable.
NUM_LABELS = 2
LABEL_NAMES = ["Benign", "Threat"]
THREAT_INDEX = 1
ADAPTERS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "adapters"

ADAPTER_NAME_MAP = {
    "bec": "bec_adapter",
    "fake_invoice": "fake_invoice_adapter",
    "ceo_fraud": "ceo_fraud_adapter",
    "credential_harvest": "credential_harvesting_adapter",
    "tax_impersonation": "tax_impersonation_adapter",
}


class BaseModel:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.model = None
            cls._instance.tokenizer = None
            cls._instance.loaded = False
        return cls._instance

    def load_if_needed(self):
        if self.loaded and self.model is not None:
            return
        if not HAS_ML_DEPS:
            return
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                BASE_MODEL_NAME, num_labels=NUM_LABELS
            )
            self.loaded = True
            logger.info("Base model loaded: %s (num_labels=%d)", BASE_MODEL_NAME, NUM_LABELS)
        except Exception as e:
            logger.error("Failed to load base model: %s", e)
            self.model = None
            self.tokenizer = None
            self.loaded = False


_base_model = BaseModel()


def adapter_path_for(category: str) -> Path:
    adapter_name = ADAPTER_NAME_MAP.get(category, f"{category}_adapter")
    return ADAPTERS_DIR / adapter_name


# Kept for callers that used the old private name.
_resolve_adapter_path = adapter_path_for


class AdapterRegistry:
    """Holds every adapter inside one PEFT model and switches between them.

    The previous code called `PeftModel.from_pretrained(base.model, path)` on
    every single inference. That call does not return an independent model: it
    injects LoRA layers into the object it is handed, and the object here was
    the shared base-model singleton. So the second category's adapter was
    grafted onto a base that already carried the first one, the third onto
    both, and so on — PEFT says as much ("Already found a `peft_config`
    attribute in the model. This will lead to having multiple adapters"). The
    classifier head, which is a `modules_to_save` entry rather than a LoRA
    delta, was replaced outright each time, so after the first message every
    verdict came from a mixture of adapters over whichever head happened to
    land last.

    Loading each adapter once by name and calling `set_adapter` before each
    inference gives exactly one active adapter over a clean base, which is
    what the training produced and what the confidence threshold assumes. It
    also stops re-reading the weights from disk on every email.
    """

    def __init__(self):
        self.model = None
        self.names: set[str] = set()

    def activate(self, category: str, adapter_path: Path):
        if self.model is None:
            self.model = PeftModel.from_pretrained(
                _base_model.model, str(adapter_path), adapter_name=category
            )
            self.model.eval()
            self.names.add(category)
        elif category not in self.names:
            self.model.load_adapter(str(adapter_path), adapter_name=category)
            self.names.add(category)
        self.model.set_adapter(category)
        return self.model


_registry = AdapterRegistry()
# The scoring routes run in FastAPI's thread pool so a long inference cannot
# block /health. The adapters share one PeftModel, and `set_adapter` switches
# it globally, so activation and inference must happen as one step.
_inference_lock = threading.Lock()


def run(base_model: BaseModel, category: str, message) -> dict:
    """
    Runs the LoRA adapter inference if the adapter is trained and available.
    Falls back to a simulated response when the adapter or ML deps are missing.

    `message` is a dict with sender/subject/body. A bare string is accepted and
    treated as the body, which is what the older callers passed.
    """
    adapter_path = _resolve_adapter_path(category)
    base_model = _base_model
    formatted_text = _format_input(message)

    if not HAS_ML_DEPS:
        return _simulate(category, formatted_text)

    with _inference_lock:
        base_model.load_if_needed()
    if base_model.model is None or base_model.tokenizer is None:
        return _simulate(category, formatted_text)

    if not adapter_path.exists() or not adapter_path.is_dir():
        logger.warning("No adapter found for category '%s' at %s — falling back to simulation", category, adapter_path)
        return _simulate(category, formatted_text)

    try:
        inputs = base_model.tokenizer(formatted_text, return_tensors="pt", truncation=True, max_length=512)
        with _inference_lock:
            peft_model = _registry.activate(category, adapter_path)
            with torch.no_grad():
                outputs = peft_model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)

        row = probs[0]
        predicted_idx = int(row.argmax().item())

        # Confidence is P(Threat) directly.
        #
        # The old formula was `1 - P(Safe)` over five classes, which treated
        # "not confidently safe" as "confidently malicious": a merely undecided
        # model puts ~0.3 on Safe and so scored 0.7, tripping the confirm
        # threshold on its own. Ordinary mail was flagged by model uncertainty
        # alone. With a binary head the two readings coincide and the number
        # means what the threshold assumes it means.
        threat_confidence = float(row[THREAT_INDEX].item())

        return {
            "confidence": round(threat_confidence, 3),
            "category": category,
            "model": "ModernBERT-base + LoRA (Real)",
            "adapter": category,
            "adapter_path": str(adapter_path),
            "predicted_label": LABEL_NAMES[predicted_idx],
            "label_probs": {LABEL_NAMES[i]: round(row[i].item(), 3) for i in range(NUM_LABELS)},
        }
    except Exception as e:
        logger.error("Adapter inference failed for '%s': %s — falling back to simulation", category, e)
        return _simulate(category, formatted_text)


def run_all(enabled_categories: list, message) -> list:
    """
    Control flow: If Tier 0 did not prove scam, check ALL categories with
    their LoRA adapters to find which specific scam type (if any) matches.
    Returns a list of results from every adapter that ran.
    """
    results = []
    for cat in enabled_categories:
        result = run(_base_model, cat, message)
        results.append(result)
    return results


def _format_input(message) -> str:
    """Reproduce the string the adapters were trained on, exactly.

    `train_tier1.py` encodes every example as

        Sender: <sender> | Subject: <subject> | Body: <body>

    Serving used to send `[Category: Business Email Compromise] <body>`
    instead — a prefix the adapter had never seen, with the sender and subject
    missing entirely. The model was being asked about a differently shaped
    input than the one it learned on, which costs accuracy for no reason. The
    category no longer needs naming in the text because each adapter answers
    for its own category.
    """
    if isinstance(message, dict):
        sender = (message.get("sender") or "").strip()
        subject = (message.get("subject") or "").strip()
        body = (message.get("body") or "").strip()
    else:
        sender, subject, body = "", "", (message or "").strip()
    return f"Sender: {sender} | Subject: {subject} | Body: {body}"[:2048]


def _simulate(category: str, email_text: str) -> dict:
    lower_text = (email_text or "").lower()
    keywords = {
        "bec": ["urgent", "wire", "invoice", "transfer"],
        "fake_invoice": ["invoice", "overdue", "payment", "billing"],
        "ceo_fraud": ["ceo", "urgent request", "confidential", "wire"],
        "credential_harvest": ["password", "login", "verify", "account"],
        "tax_impersonation": ["irs", "tax", "penalty", "refund"],
    }
    target_words = keywords.get(category, [])
    hits = sum(1 for w in target_words if w in lower_text)
    base = 0.1 + (hits * 0.15)
    jitter = (len(lower_text) % 100) / 1000.0
    confidence = min(0.65, base + jitter)
    return {
        "confidence": round(confidence, 3),
        "category": category,
        "model": "ModernBERT-base + LoRA (Simulated)",
        "adapter": category,
    }
