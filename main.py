from lib import (
    CandidateGenerator,
    ParallelCracker,
    PasswordHasher,
    SequentialCracker,
    get_cpu_count,
)

# --- Набори символів (п. 2 методички) ---
uppChar = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lowChar = "abcdefghijklmnopqrstuvwxyz"
numChar = "0123456789"
spcChar = "!@#$%^&*_-"

# --- Варіант 2 (таблиці 1 і 2 методички) ---
LENGTH = 6
CHARSET = uppChar + spcChar
ALGORITHM = "sha384"
TARGET_HASH = (
    "1dff50155be465154c592e6f926cf44cc42005cf66e9dda9"
    "3394561914ce5eae8bfceeed77f21586d3975547136b172e"
)


def main():
    """Виводить n_cpu, а потім результати послідовного та паралельного підбору пароля."""
    n_cpu = get_cpu_count()
    print(f"Кількість процесорних ядер (n_cpu): {n_cpu}")

    hasher = PasswordHasher(ALGORITHM)

    # а) без мультипроцесорності
    sequential = SequentialCracker(hasher, TARGET_HASH)
    generator = CandidateGenerator(CHARSET, LENGTH)
    password_seq, time_seq = sequential.crack(generator)
    print(f"[Без мультипроцесорності] Пароль: {password_seq}, час: {time_seq:.4f} с")

    # б) з використанням Pool, кількість процесів = n_cpu
    parallel = ParallelCracker(CHARSET, LENGTH, ALGORITHM, TARGET_HASH, n_processes=n_cpu)
    password_par, time_par = parallel.crack()
    print(f"[З Pool, {n_cpu} процес(ів)] Пароль: {password_par}, час: {time_par:.4f} с")


if __name__ == "__main__":
    main()
