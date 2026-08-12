import re #regex module is imported to use regular expressions for pattern matching in the prompt text. This is essential for detecting any jailbreak attempts or suspicious patterns in the input prompt.
from transformers import pipeline #charger et utliser le prompt guard 
import torch #les tenseurs représentent des tableaux multidimensionnels et sont utilisés pour stocker les entrées, les poids du modèle et les sorties. PyTorch fournit des opérations optimisées sur ces tenseurs, ce qui est crucial pour l'entraînement et l'inférence des modèles de deep learning.
from transformers import AutoTokenizer, AutoModelForSequenceClassification


JAILBREAK_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above) (instructions|rules)",
    r"you are now (in )?(dan|jailbreak|developer) mode",
    r"reveal (your |the )?(system prompt|instructions)",
    r"pretend (you have no|to have no) (restrictions|rules|filters)",
    r"act as if you (have no|had no) (guidelines|restrictions)",
    r"forget (everything|all) (you('ve| have) been told|above)",
    r"\bDAN\b",
]

MAX_PROMPT_LENGTH = 4000  # caractères — seuil "longueur anormale", à ajuster après tests

class GuardrailViolation(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason) #this line calls the constructor of the base Exception class with the reason for the violation, allowing the exception to carry a message that can be used for logging or user feedback.   


MODEL_THRESHOLD = 0.5  # point de départ — à ajuster après le benchmark ci-dessous

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M" 
# Mapping label brut -> sens, PAR modèle — le nombre de classes et leur ordre
# ne sont pas garantis identiques d'un modèle à l'autre.
_LABEL_MAPS = {
    "meta-llama/Llama-Prompt-Guard-2-86M": {
        "LABEL_0": "BENIGN",
        "LABEL_1": "MALICIOUS",
    },
}


_classifier = None  # chargement paresseux : le modèle met du temps à charger,
                     # on ne veut pas le refaire à chaque import du module

def _get_classifier():
    global _classifier
    if _classifier is None:
        _classifier = pipeline("text-classification", model="meta-llama/Llama-Prompt-Guard-2-86M")
    return _classifier

_tokenizer = None #tokenizer will be used to convert the input prompt into a format that the model can understand. 
_model = None #model will be used to classify the input prompt as either benign or malicious based on the learned patterns from the training data.

def _load():
    global _tokenizer, _model
    if _model is None:
        model_id = "meta-llama/Llama-Prompt-Guard-2-86M"
        _tokenizer = AutoTokenizer.from_pretrained(model_id) #here the tokenizer is loaded from the pre-trained model specified by model_id. The tokenizer is responsible for converting the input text into a format that the model can understand, typically by breaking it down into tokens and encoding them into numerical representations.
        _model = AutoModelForSequenceClassification.from_pretrained(model_id) #AutoModel
    return _tokenizer, _model


def classify_with_model(prompt: str) -> tuple[str, float]:
    tokenizer, model = _load()
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512) #return_tensors="pt" indicates that the tokenizer should return PyTorch tensors, which are the data structures used by PyTorch for model input. truncation=True ensures that if the prompt exceeds the maximum length of 512 tokens, it will be truncated to fit within this limit. This is important because many models have a maximum input length they can handle, and exceeding this length can lead to errors or unexpected behavior.
    #truncation=True ensures that if the prompt exceeds the maximum length of 512 tokens, it will be truncated to fit within this limit. This is important because many models have a maximum input length they can handle, and exceeding this length can lead to errors or unexpected behavior.
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    predicted_id = probs.argmax().item()
    raw_label = model.config.id2label[predicted_id]
    score = probs[predicted_id].item()

    label_map = _LABEL_MAPS.get(MODEL_ID)
    if label_map is None:
        raise RuntimeError(f"Aucun mapping de labels défini pour '{MODEL_ID}'. Ajoute une entrée dans _LABEL_MAPS.")
    label = label_map.get(raw_label)
    if label is None:
        raise RuntimeError(f"Label inattendu '{raw_label}' pour '{MODEL_ID}' — mapping incomplet.")

    return label, score


def check_prompt(prompt: str) -> None:
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise GuardrailViolation(f"Prompt trop long ({len(prompt)} caractères, max {MAX_PROMPT_LENGTH})")

    lowered = prompt.lower()
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, lowered):
            raise GuardrailViolation(f"Motif suspect détecté: '{pattern}'")

    label, score = classify_with_model(prompt)
    if label == "MALICIOUS" and score >= MODEL_THRESHOLD:
        raise GuardrailViolation(f"Prompt Guard: {label} (score={score:.2f})")
