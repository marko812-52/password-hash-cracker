# 🔐 Password Hash Cracker: sequential vs. multiprocessing

Recovers a password from its **SHA-384** hash by brute force and compares a single-process search
with a parallel one on all CPU cores (`multiprocessing.Pool`). A second script estimates how long
brute force would take for different password policies, to show why **length beats complexity**.

> Built as a university lab (Lviv Polytechnic, "Scripting Languages", lab 2), then extended.
> For education only: run it against hashes you created yourself.

## Run

```bash
python main.py       # crack the lab hash: 6 chars, A–Z + !@#$%^&*_-
python estimate.py   # crack-time table for different policies
```

## How the parallel search works

The keyspace is split by the **first character**: each process gets its own set of first characters
and tries every combination of the rest. `imap_unordered` returns results as soon as any worker finishes;
when one finds the password, `pool.terminate()` stops the others.

Classes follow the Single Responsibility Principle: `PasswordHasher` (hashing), `CandidateGenerator`
(candidates), `SequentialCracker` and `ParallelCracker` (search strategies).

## Sample output of `estimate.py`

Worst-case time to try the whole keyspace with SHA-384 in pure Python on 2 CPU cores (~2.2 M hashes/s):

| policy | 6 chars | 8 chars | 12 chars | 16 chars |
|---|---|---|---|---|
| digits only | 0.5 s | 45 s | 5 d | 141 yr |
| lowercase | 2 min | 1 d | 1,348 yr | 6.2e+08 yr |
| lower + upper + digits | 7 h | 3 yr | 4.6e+07 yr | 6.7e+14 yr |
| all printable symbols | 4 d | 86 yr | 6.7e+09 yr | 5.2e+17 yr |

A GPU with hashcat is roughly 1000× faster, so real attackers are much quicker.

## What I learned

- Fast hashes (MD5, SHA-1, SHA-2) are a bad fit for storing passwords: they are designed to be fast,
  which helps attackers. Password storage needs slow, salted hashes: **bcrypt, scrypt, Argon2**.
- Adding 4 characters of length does more than adding symbols to the charset.
- Parallelism scales roughly with the number of cores, but process start-up has a cost,
  so for tiny keyspaces the sequential version is faster.

**Stack:** Python · hashlib · itertools · multiprocessing
