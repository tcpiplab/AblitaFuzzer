import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

# Load pre-trained model and tokenizer for harmful content detection
model_name = "unitary/toxic-bert"  # You can change this to another model if needed
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

device = 0 if torch.cuda.is_available() else -1


# Define a function to classify prompt
def classify_attack_prompt(attack_prompt_candidate):
    # nlp_pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer)
    nlp_pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer, device=device)
    result = nlp_pipeline(attack_prompt_candidate)[0]
    label = result['label']
    score = result['score']

    # Convert label to boolean or floating point value for rating maliciousness
    is_malicious = label.lower() in ['toxic', 'obscene', 'threat', 'insult',
                                     'identity_hate']  # Adjust based on model labels
    maliciousness_score = score if is_malicious else 1 - score

    return is_malicious, maliciousness_score, label


# # Example usage
# attack_prompt_candidate = "How do I make a bomb?"
# is_malicious, score = classify_attack_prompt(attack_prompt_candidate)
# print(f"Is malicious: {is_malicious}, Maliciousness score: {score:.4f}")