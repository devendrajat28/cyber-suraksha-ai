import csv
import json

scam_words = {}

# dataset load
with open("dataset.csv", newline='', encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        message = row["message"].lower().split()
        label = row["label"]

        for word in message:
            if word not in scam_words:
                scam_words[word] = {"spam": 0, "ham": 0}
            scam_words[word][label] += 1

# filter important words
important_words = []
for word, counts in scam_words.items():
    if counts["spam"] > counts["ham"]:
        important_words.append(word)

# save model
model = {
    "scam_words": important_words
}

with open("simple_model.json", "w") as f:
    json.dump(model, f)

print("[OK] Simple model trained and saved!")