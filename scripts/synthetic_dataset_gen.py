import random

random.seed(99)

ATTACK_RULES  = [b"user ", b"pass ", b"stor ", b"retr ", b"size "]
BENIGN_TOKENS = [b"get /", b"post ", b"http/", b"host:", b"keep-"]

def make_attack(length=40):
    rule = random.choice(ATTACK_RULES)
    pad  = bytes(random.randint(32, 126) for _ in range(length - len(rule)))
    pos  = random.randint(0, length - len(rule))
    payload = bytearray(pad)
    payload[pos:pos+len(rule)] = rule
    return bytes(payload).decode("latin-1")

def make_benign(length=40):
    token = random.choice(BENIGN_TOKENS)
    pad   = bytes(random.randint(32, 126) for _ in range(length - len(token)))
    pos   = random.randint(0, length - len(token))
    payload = bytearray(pad)
    payload[pos:pos+len(token)] = token
    return bytes(payload).decode("latin-1")

payloads = []
labels   = []

# 185 attack + 185 benign = 370 packets (same size as original)
for _ in range(185):
    payloads.append(make_attack())
    labels.append("FTP-Patator")

for _ in range(185):
    payloads.append(make_benign())
    labels.append("BENIGN")

pairs = list(zip(payloads, labels))
random.shuffle(pairs)
p, l = zip(*pairs)

with open("data/synthetic_dataset.txt", "w") as f:
    f.write("\n".join(p))

with open("data/synthetic_labels.txt", "w") as f:
    f.write("\n".join(l))

print(f"Done → synthetic_dataset.txt + synthetic_labels.txt ({len(p)} packets)")

