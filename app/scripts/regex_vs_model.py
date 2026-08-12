import re
from datasets import load_dataset
from app.runtime.input_guardrails.input_guardrails import classify_with_model, JAILBREAK_PATTERNS, MODEL_THRESHOLD

ds = load_dataset("deepset/prompt-injections")["train"]
 #this line loads the "prompt-injections" dataset from the "deepset" repository using the `load_dataset` function from the `datasets` library. The dataset is split into different subsets (e.g., train, test, validation), and this line specifically selects the "train" subset for further processing and evaluation of prompt injection detection methods.
print(ds.features)  # vérifie les noms de colonnes réels avant d'adapter le script ci-dessous

def heuristics_only(text: str) -> bool:
    lowered = text.lower()
    return any(re.search(p, lowered) for p in JAILBREAK_PATTERNS)

def heuristics_plus_model(text: str) -> bool:
    h = heuristics_only(text)
    label, score = classify_with_model(text)
    print(f"heuristic={h} | model={label} | score={score:.4f}")
    if h:
        return True
    return label == "MALICIOUS" and score >= MODEL_THRESHOLD


def evaluate(predict_fn, dataset):
    tp = fp = tn = fn = 0 #these variables are initialized to zero to keep track of the counts of true positives (tp), false positives (fp), true negatives (tn), and false negatives (fn) during the evaluation of the prediction function against the dataset.
    for row in dataset:
        actual = bool(row["label"])          # adapte le nom de colonne selon ds.features
        predicted = predict_fn(row["text"])   # idem
        if predicted and actual: tp += 1
        elif predicted and not actual: fp += 1
        elif not predicted and actual: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall}

print("Heuristiques seules   :", evaluate(heuristics_only, ds))
print("Heuristiques + modèle :", evaluate(heuristics_plus_model, ds))