"""Tier 1 specialist adapter training (ModernBERT-base + LoRA).

Earlier runs of this script were diagnosed as overfitting. They were not. The
five-level severity target is roughly half noise, and the measurements are
unambiguous — accuracy on templates held out of training, using a linear
TF-IDF baseline so the model itself is not the variable:

    benign vs threat      1.000
    Safe   vs Low         0.476     (chance is 0.500)
    High   vs Critical    0.503     (guessing the majority gives 0.716)

Two of the four distinctions are not merely hard, they are anti-informative:
the same subject template appears as both High and Critical, and the level is
driven by a separate `indicators` annotation rather than by anything in the
wording. Fitting that target caps any model at roughly 55% and produced the
"wrong" verdicts, because ~45% of its error was an arbitrary High/Critical coin
flip. No amount of regularisation, capacity or training time repairs a label
that is independent of its input.

So this trains the distinction that is real and that the engine actually
consumes: is this message an instance of the threat category, or not. The
cascade already reduces the adapter output to exactly that question before
acting on it.

Honesty about what the headline number means: the separation is near-perfect
because the corpus is synthetic and its benign and malicious vocabularies do
not overlap ("PO on file", "manager approval" versus "wire today", "do not
forward"). Real mail is not drawn that cleanly, so treat the score below as
evidence the pipeline is sound, not as a forecast of field accuracy. The
learning curve and the train/eval gap printed at the end are the numbers that
say whether this run over- or underfits.
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import GroupShuffleSplit
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
    set_seed,
)

SEED = 42
set_seed(SEED)

BASE_MODEL_NAME = "answerdotai/ModernBERT-base"
# Adapter directory name -> corpus file stem. The engine calls the credential
# adapter "credential_harvest"; its corpus is "credential_harvesting".
CATEGORY_FILES = {
    "bec": "bec",
    "fake_invoice": "fake_invoice",
    "ceo_fraud": "ceo_fraud",
    "credential_harvesting": "credential_harvesting",
    "tax_impersonation": "tax_impersonation",
}
# Pass the category as the first argument; defaults to bec so the bare
# `python train_tier1.py` invocation keeps working.
TARGET_CATEGORY = sys.argv[1] if len(sys.argv) > 1 else "bec"
if TARGET_CATEGORY not in CATEGORY_FILES:
    raise SystemExit(
        f"Unknown category {TARGET_CATEGORY!r}; expected one of {', '.join(CATEGORY_FILES)}")
DATA_FILE_STEM = CATEGORY_FILES[TARGET_CATEGORY]
ADAPTER_OUTPUT_DIR = f"./adapters/{TARGET_CATEGORY}_adapter"

# Must match `thresholds.tier1_confirm` in desktop-app/data/config.json. The
# adapter is only useful above this line, so it is the line to measure at.
SERVING_THRESHOLD = 0.85

# The engine's contract: index 0 is "not this threat", index 1 is "this threat".
LABEL_NAMES = ["Benign", "Threat"]
LABEL_MAP = {name: i for i, name in enumerate(LABEL_NAMES)}
ID2LABEL = {i: name for name, i in LABEL_MAP.items()}

# Severity levels that mean "this is the threat". Medium-High is included for
# completeness even though the BEC corpus never uses it.
THREAT_LEVELS = {"Medium-High", "High", "Critical"}

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)


def corpus_path(stem):
    """Prefer the augmented corpus when `augment_corpus.py` has been run.

    The original files are formulaic enough that an adapter can score 1.000 on
    held-out templates by recognising an artefact — all 2100 credential
    harvesting attacks carry a display/real URL mismatch, so the model learned
    that rather than the demand for credentials. The augmented file adds the
    attack styles each corpus omits, plus benign mail using the same
    vocabulary honestly.
    """
    augmented = Path(f"{stem}_dataset_augmented.json")
    return augmented if augmented.exists() else Path(f"{stem}_dataset.json")


def load_corpus(stem):
    """One corpus, deduplicated, with contradictory annotations dropped."""
    with open(corpus_path(stem), encoding="utf-8") as f:
        rows = json.load(f)

    by_text = defaultdict(list)
    for row in rows:
        by_text[(row["sender"], row["subject"], row["body"])].append(row["threat_level"])

    clean, conflicts = [], 0
    for (sender, subject, body), levels in by_text.items():
        if len(set(levels)) > 1:
            # The same message annotated two ways: no target to fit.
            conflicts += 1
            continue
        clean.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "level": levels[0],
            "is_threat": levels[0] in THREAT_LEVELS,
        })
    return clean, len(rows), len(rows) - len(by_text), conflicts


def load_clean_rows():
    """Build a one-vs-rest training set for TARGET_CATEGORY.

    Positives are this category's own attacks. Negatives are benign mail from
    *every* corpus, this one and the other four.

    Training on one corpus alone was the first mistake: "Benign" then meant
    only "the harmless mail that happens to sit in this category's file", so an
    adapter had seen a narrow slice of ordinary mail and fired loosely on
    anything scam-shaped.

    Adding the other categories' *attacks* as negatives was the second
    mistake, and a more instructive one. It produced a perfect confusion
    matrix — 1.000 on the diagonal, 0.000 everywhere else — and adapters that
    scored 0.0 on hand-written mail describing exactly their own scam in
    different words. Because each corpus uses its own narrow vocabulary,
    "is this my category" collapses into "which corpus did this wording come
    from", and a model can ace that without learning anything about fraud. The
    diagonal was measuring corpus identification, not detection.

    So negatives are benign mail only. That widens what the adapter knows
    ordinary mail to look like, which is the real defence against false
    positives, without handing it a corpus-vocabulary shortcut. Adapters will
    still fire on each other's attacks; on this data that overlap is genuine
    signal (an invoice-fraud email and a CEO-fraud email share most of their
    pressure tactics), and for flagging it is redundancy rather than error.
    The cost is that the category label beside a verdict is the best-scoring
    specialist rather than a confident attribution.
    """
    own, before, dupes, conflicts = load_corpus(DATA_FILE_STEM)
    print(f"Rows in {DATA_FILE_STEM:22s}: {before}")
    print(f"Duplicate rows removed : {dupes}")
    print(f"Contradictory texts    : {conflicts} (dropped)")

    rows = []
    for r in own:
        rows.append({**r, "label": LABEL_MAP["Threat"] if r["is_threat"] else LABEL_MAP["Benign"],
                     "source": DATA_FILE_STEM})

    for stem in CATEGORY_FILES.values():
        if stem == DATA_FILE_STEM:
            continue
        other, *_ = load_corpus(stem)
        other_benign = [r for r in other if not r["is_threat"]]
        for r in other_benign:
            rows.append({**r, "label": LABEL_MAP["Benign"], "source": stem})
        print(f"  benign negatives from {stem:22s}: {len(other_benign)}")

    print(f"Usable messages        : {len(rows)}")
    return rows


def encode(rows):
    texts = [f"Sender: {r['sender']} | Subject: {r['subject']} | Body: {r['body']}" for r in rows]
    batch = tokenizer(texts, truncation=True, max_length=512)
    batch["labels"] = [r["label"] for r in rows]
    return Dataset.from_dict(batch)


def compute_metrics(eval_pred):
    logits, gold = eval_pred
    pred = np.argmax(logits, axis=-1)
    benign = gold == LABEL_MAP["Benign"]
    return {
        "accuracy": float(np.mean(pred == gold)),
        "macro_f1": float(f1_score(gold, pred, average="macro", zero_division=0)),
        # The number the deployment was failing on: benign mail called a threat.
        "benign_false_positive_rate":
            float(np.mean(pred[benign] != LABEL_MAP["Benign"])) if benign.any() else 0.0,
    }


def build_trainer(train_rows, eval_rows, weights, epochs=6, output_dir=ADAPTER_OUTPUT_DIR):
    base_model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL_NAME,
        num_labels=len(LABEL_NAMES),
        id2label=ID2LABEL,
        label2id=LABEL_MAP,
        dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float32,
    )
    model = get_peft_model(base_model, LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        lora_dropout=0.1,
        target_modules=["Wqkv", "Wo"],
    ))

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            gold = inputs.pop("labels")
            outputs = model(**inputs)
            loss = torch.nn.functional.cross_entropy(
                outputs.logits.float(), gold, weight=weights.to(outputs.logits.device)
            )
            return (loss, outputs) if return_outputs else loss

    args = TrainingArguments(
        output_dir=output_dir,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=4,
        learning_rate=3e-5,
        num_train_epochs=epochs,
        logging_steps=25,
        save_strategy="epoch",
        eval_strategy="epoch",
        load_best_model_at_end=True,
        # Select on loss, not macro-F1.
        #
        # F1 saturates at 1.000 within an epoch on this data, and every later
        # epoch ties it. `load_best_model_at_end` keeps the first checkpoint
        # that reached the best value, so the saved adapter was the earliest,
        # least-confident one. That is exactly what happened to the credential
        # adapter: it classified correctly but averaged 0.810 confidence, and
        # the cascade's 0.85 confirm threshold meant it caught 15% of its own
        # attacks. Loss keeps falling after accuracy tops out, so it picks the
        # checkpoint that is both right and decisive.
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        bf16=torch.cuda.is_bf16_supported(),
        fp16=False,
        report_to="none",
        weight_decay=0.05,
        max_grad_norm=1.0,
        warmup_steps=20,
        save_total_limit=1,
        seed=SEED,
        disable_tqdm=True,
    )
    return WeightedTrainer(
        model=model,
        args=args,
        train_dataset=train_rows,
        eval_dataset=eval_rows,
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )


def main():
    rows = load_clean_rows()

    print("\nWhere each class comes from:")
    by_source = defaultdict(Counter)
    for r in rows:
        by_source[r["source"]][LABEL_NAMES[r["label"]]] += 1
    for source, counts in by_source.items():
        marker = "  (target)" if source == DATA_FILE_STEM else ""
        print(f"  {source:24s} {dict(counts)}{marker}")
    print("\nTraining target:", dict(Counter(LABEL_NAMES[r["label"]] for r in rows)))

    # Split on the subject template, not on the message. Messages sharing a
    # template are near-duplicates, so splitting on the message would let the
    # model recognise a phrasing it had already been trained on and report a
    # score it could not reproduce on new mail.
    groups = [r["subject"] for r in rows]
    labels = [r["label"] for r in rows]
    train_idx, eval_idx = next(
        GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED).split(rows, labels, groups)
    )
    train_rows = [rows[i] for i in train_idx]
    eval_rows = [rows[i] for i in eval_idx]

    train_subjects = {r["subject"] for r in train_rows}
    eval_subjects = {r["subject"] for r in eval_rows}
    print(f"\nTrain: {len(train_rows)} messages / {len(train_subjects)} templates")
    print(f"Eval : {len(eval_rows)} messages / {len(eval_subjects)} templates")
    print(f"Templates shared between the two: {len(train_subjects & eval_subjects)} (must be 0)")
    if train_subjects & eval_subjects:
        raise SystemExit("Template leaked across the split.")

    counts = Counter(r["label"] for r in train_rows)
    total = sum(counts.values())
    weights = torch.tensor(
        [total / (len(LABEL_NAMES) * counts[i]) for i in range(len(LABEL_NAMES))],
        dtype=torch.float,
    )
    print("Class weights:", {n: round(float(w), 2) for n, w in zip(LABEL_NAMES, weights)})

    train_ds, eval_ds = encode(train_rows), encode(eval_rows)

    trainer = build_trainer(train_ds, eval_ds, weights)
    print(f"\nFine-tuning the {TARGET_CATEGORY.upper()} adapter\n")
    trainer.train()

    # ---- over/underfitting check -------------------------------------------
    train_metrics = trainer.evaluate(eval_dataset=train_ds, metric_key_prefix="train")
    eval_metrics = trainer.evaluate(eval_dataset=eval_ds, metric_key_prefix="eval")
    gap = train_metrics["train_accuracy"] - eval_metrics["eval_accuracy"]
    print("\nFit diagnosis")
    print(f"  accuracy on training data : {train_metrics['train_accuracy']:.3f}")
    print(f"  accuracy on unseen templates: {eval_metrics['eval_accuracy']:.3f}")
    print(f"  generalisation gap        : {gap:+.3f}")
    if gap > 0.10:
        print("  -> overfitting: it is memorising training templates")
    elif eval_metrics["eval_accuracy"] < 0.80:
        print("  -> underfitting: it has not captured the signal that is there")
    else:
        print("  -> fits well: high on unseen templates with a small gap")

    predictions = trainer.predict(eval_ds)
    pred = np.argmax(predictions.predictions, axis=-1)
    gold = predictions.label_ids
    print("\nHeld-out report (templates never seen in training)")
    print(classification_report(gold, pred, target_names=LABEL_NAMES, zero_division=0))
    benign = gold == LABEL_MAP["Benign"]
    print(f"Benign mail called a threat: {int(np.sum(pred[benign] != LABEL_MAP['Benign']))}"
          f"/{int(benign.sum())} ({np.mean(pred[benign] != LABEL_MAP['Benign']):.1%})")

    # Argmax accuracy is not what the engine acts on. The cascade confirms a
    # threat only when confidence clears `tier1_confirm`, so an adapter that is
    # right but hesitant still misses everything. Report the number the
    # deployment is judged by.
    logits = torch.tensor(predictions.predictions, dtype=torch.float)
    confidence = torch.softmax(logits, dim=-1)[:, LABEL_MAP["Threat"]].numpy()
    threat = gold == LABEL_MAP["Threat"]
    print(f"\nAt the serving threshold ({SERVING_THRESHOLD}):")
    print(f"  own attacks confirmed    : {np.mean(confidence[threat] >= SERVING_THRESHOLD):.1%}"
          f"  (mean confidence {confidence[threat].mean():.3f})")
    print(f"  negatives wrongly confirmed: {np.mean(confidence[benign] >= SERVING_THRESHOLD):.1%}"
          f"  (mean confidence {confidence[benign].mean():.3f})")
    if np.mean(confidence[threat] >= SERVING_THRESHOLD) < 0.90:
        print("  -> WARNING: correct but under-confident; the cascade will miss these")

    trainer.model.save_pretrained(ADAPTER_OUTPUT_DIR)
    tokenizer.save_pretrained(ADAPTER_OUTPUT_DIR)
    print(f"\nAdapter saved to {ADAPTER_OUTPUT_DIR}")


if __name__ == "__main__":
    main()
