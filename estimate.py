"""Estimate how long a brute-force attack would take for different password policies.

Measures this machine's real hash rate, then extrapolates to the full keyspace
(charset_size ** length). Shows why length matters more than "complexity".
"""

import string
import time

from lib import PasswordHasher, get_cpu_count

POLICIES = {
    "digits only": string.digits,
    "lowercase": string.ascii_lowercase,
    "lower + upper": string.ascii_letters,
    "lower + upper + digits": string.ascii_letters + string.digits,
    "all printable symbols": string.ascii_letters + string.digits + string.punctuation,
}
LENGTHS = (6, 8, 10, 12, 16)


def measure_hash_rate(algorithm: str, seconds: float = 1.0) -> float:
    """Hashes per second on one CPU core for the given algorithm."""
    hasher = PasswordHasher(algorithm)
    count, start = 0, time.perf_counter()
    while time.perf_counter() - start < seconds:
        hasher.compute(f"pw{count}")
        count += 1
    return count / (time.perf_counter() - start)


def human_time(seconds: float) -> str:
    """Turns seconds into a short readable string (s, min, h, d, yr)."""
    for unit, size in (("yr", 31_557_600), ("d", 86_400), ("h", 3_600), ("min", 60)):
        if seconds >= size:
            value = seconds / size
            return f"{value:.1e} {unit}" if value >= 1e4 else f"{value:,.0f} {unit}"
    return f"{seconds:.2f} s"


def main(algorithm: str = "sha384") -> None:
    cores = get_cpu_count() or 1
    rate = measure_hash_rate(algorithm) * cores
    print(f"{algorithm}: ~{rate:,.0f} hashes/s on {cores} CPU cores (Python, no GPU)\n")
    header = f"{'policy':<26}" + "".join(f"{n:>14}" for n in LENGTHS)
    print(header)
    print("-" * len(header))
    for name, charset in POLICIES.items():
        worst = [len(charset) ** n / rate for n in LENGTHS]
        print(f"{name:<26}" + "".join(f"{human_time(t):>14}" for t in worst))
    print("\nWorst case = whole keyspace. A GPU (hashcat) is ~1000x faster,")
    print("so treat these numbers as a lower bound for an attacker.")


if __name__ == "__main__":
    main()
