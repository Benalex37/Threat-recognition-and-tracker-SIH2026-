import argparse
import json
import torch
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from peft import get_peft_model, LoraConfig, TaskType

def load_data(jsonl_path):
    texts = []
    labels = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            texts.append(data['text'])
            labels.append(data['label'])
    return Dataset.from_dict({"text": texts, "label": labels})

def train(category, data_path, output_dir):
    print(f"Loading data for {category} from {data_path}...")
    dataset = load_data(data_path)
    
    # ModernBERT-base
    model_name = "answerdotai/ModernBERT-base"
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    
    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=512)
    
    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    
    # 2 labels: 0 (safe/other), 1 (this category)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    # Configure LoRA
    peft_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        lora_dropout=0.1,
        target_modules=["query", "value"] # Adjust target modules for ModernBERT as necessary
    )
    
    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()
    
    training_args = TrainingArguments(
        output_dir=f"./results_{category}",
        learning_rate=2e-4,
        per_device_train_batch_size=8,
        num_train_epochs=3,
        weight_decay=0.01,
        save_strategy="epoch"
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset,
    )
    
    print(f"Starting training for {category} adapter...")
    trainer.train()
    
    import os
    save_path = os.path.join(output_dir, category)
    print(f"Saving adapter to {save_path}...")
    model.save_pretrained(save_path)
    print("Done!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train a LoRA adapter for a specific email threat category.")
    parser.add_argument("--category", type=str, required=True, help="Category name (e.g., bec, ceo_fraud)")
    parser.add_argument("--data", type=str, required=True, help="Path to JSONL training data (with 'text' and 'label' fields)")
    parser.add_argument("--output", type=str, default="../app/adapters", help="Output directory for the adapter")
    
    args = parser.parse_args()
    train(args.category, args.data, args.output)
