import random

SEED = 42

with open("data/cicids_dataset_shuffled.txt") as f:
    payloads = f.read().splitlines()

with open("data/cicids_labels_shuffled.txt") as f:
    labels = f.read().splitlines()

pairs = list(zip(payloads, labels))
random.seed(SEED)
random.shuffle(pairs)

p2, l2 = zip(*pairs)

with open("data/cicids_dataset_shuffled2.txt", "w") as f:
    f.write("\n".join(p2))

with open("data/cicids_labels_shuffled2.txt", "w") as f:
    f.write("\n".join(l2))

print("Done → cicids_dataset_shuffled2.txt + cicids_labels_shuffled2.txt")
