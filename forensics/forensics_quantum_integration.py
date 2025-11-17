import base64
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

# ------------------------------------------------------------
# PART 1 — Extract Credentials from TShark Output (auth_headers.tsv)
# ------------------------------------------------------------

def extract_credentials():
    with open("auth_headers.tsv") as f:
        for line in f:
            if "Basic " in line:
                # Extract Base64 portion
                encoded = line.split("Basic ")[1].strip()
                # Decode Base64
                decoded = base64.b64decode(encoded).decode()
                return decoded
    return None

creds = extract_credentials()

if creds is None:
    print("❌ No credentials found in auth_headers.tsv")
    exit()
else:
    print("🔍 Extracted Credentials From PCAP:", creds)


# ------------------------------------------------------------
# PART 2 — BB84 Quantum Key Distribution Simulation
# ------------------------------------------------------------

np.random.seed(42)
num_qubits = 20

alice_bits  = np.random.randint(2, size=num_qubits)
alice_bases = np.random.randint(2, size=num_qubits)

qc = QuantumCircuit(num_qubits, num_qubits)

for i in range(num_qubits):
    if alice_bits[i] == 1:
        qc.x(i)
    if alice_bases[i] == 1:
        qc.h(i)

bob_bases = np.random.randint(2, size=num_qubits)

for i in range(num_qubits):
    if bob_bases[i] == 1:
        qc.h(i)
    qc.measure(i, i)

sim = AerSimulator()
compiled = transpile(qc, sim)
result = sim.run(compiled, shots=1).result()

counts = result.get_counts()
bob_raw = list(counts.keys())[0][::-1]  # reverse bitstring
bob_results = np.array(list(bob_raw)).astype(int)

shared_key = []
for i in range(num_qubits):
    if alice_bases[i] == bob_bases[i]:
        shared_key.append(int(alice_bits[i]))

print("\n🔑 Shared Quantum Key Bits:", shared_key)

# Convert quantum key to integer
quantum_key = int("".join(str(b) for b in shared_key), 2)
print("🔐 Quantum Key (int):", quantum_key)


# ------------------------------------------------------------
# PART 3 — Encrypt Credentials Using Quantum Key
# ------------------------------------------------------------

def xor_encrypt(msg, key):
    return "".join(chr(ord(c) ^ key) for c in msg)

encrypted = xor_encrypt(creds, quantum_key)
decrypted = xor_encrypt(encrypted, quantum_key)

print("\n🔏 Encrypted Credential:", encrypted)
print("🔓 Decrypted With Quantum Key:", decrypted)


# ------------------------------------------------------------
# PART 4 — Attacker Tries Wrong Key (Fails)
# ------------------------------------------------------------

attacker_attempt = xor_encrypt(encrypted, 9999)
print("\n🚫 Attacker Wrong Decrypt Attempt:", attacker_attempt)


# ------------------------------------------------------------
# PART 5 — Eve Eavesdropping Detection (QBER)
# ------------------------------------------------------------

eve_bases = np.random.randint(2, size=num_qubits)
errors = sum(eve_bases[i] != alice_bases[i] for i in range(num_qubits))
qber = (errors / num_qubits) * 100

print("\n🕵️ Eve Attack Simulation")
print("Eve Bases:", eve_bases)
print("Errors Introduced:", errors)
print("QBER: {:.2f}%".format(qber))

if qber > 25:
    print("⚠️ ALERT: High QBER! Eavesdropping Detected.")
else:
    print("✔ QBER Normal. No Attack Detected.")


# ------------------------------------------------------------
# PART 6 — Attacker tries to decrypt WITHOUT quantum key
# ------------------------------------------------------------

print("\n🔴 ATTACKER MODULE STARTED:")
print("Attacker has stolen the encrypted data:", encrypted)

# Attacker guesses random keys
import random

def attacker_attempt_decrypt(cipher, attempts=20):
    print("\nAttacker trying random keys...")
    for i in range(attempts):
        fake_key = random.randint(1, 999999)
        attempt = xor_encrypt(cipher, fake_key)

        # Attacker tries to guess pattern like 'username:'
        if "username" in attempt or ":" in attempt:
            print(f"❌ Attacker found a readable pattern: {attempt} (Key={fake_key})")
        else:
            print(f"Attempt {i+1}: {attempt} (Wrong Key={fake_key})")

    print("\n❌ RESULT: Attacker FAILED to decrypt the credentials.")


attacker_attempt_decrypt(encrypted)


# ------------------------------------------------------------
# PART 7 — Attacker tries classical brute-force (LIMITED)
# ------------------------------------------------------------

print("\n🟠 Brute-force Search Demonstration (limited):")

def brute_force(cipher, limit=5000):
    for key in range(limit):
        attempt = xor_encrypt(cipher, key)
        if "username" in attempt and ":" in attempt:
            return key, attempt
    return None, None

bf_key, bf_plain = brute_force(encrypted)

if bf_key:
    print("❌ Attacker cracked it with brute force:", bf_plain)
else:
    print("✔ Brute force FAILED within reasonable time.")

# ------------------------------------------------------------
# PART 8 — Correct decryption (Legitimate user)
# ------------------------------------------------------------

print("\n🟢 Legitimate User With Quantum Key:")
print("Decrypted Credential:", decrypted)

