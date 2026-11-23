"""SRP: кожен клас відповідає за одну задачу з підбору пароля за хешем."""

import hashlib
import itertools
import os
import time
from multiprocessing import Pool


def get_cpu_count():
    """Повертає кількість процесорних ядер, доступних системі."""
    return os.cpu_count()


class PasswordHasher:
    """Відповідає лише за обчислення хешу пароля заданим алгоритмом."""

    def __init__(self, algorithm_name):
        self._algorithm_name = algorithm_name

    def compute(self, password):
        """Повертає hex-дайджест хешу рядка password у кодуванні utf-8."""
        hash_obj = hashlib.new(self._algorithm_name, password.encode("utf-8"))
        return hash_obj.hexdigest()


class CandidateGenerator:
    """Відповідає лише за генерацію кандидатів заданої довжини з набору символів."""

    def __init__(self, charset, length):
        self._charset = charset
        self._length = length

    def generate(self):
        """Повертає генератор усіх комбінацій символів charset довжини length."""
        for combo in itertools.product(self._charset, repeat=self._length):
            yield "".join(combo)

    def generate_chunk(self, first_chars):
        """Повертає генератор кандидатів, перший символ яких належить first_chars.

        Використовується для розподілу простору паролів між процесами:
        кожен процес перебирає лише кандидатів зі «своїми» першими символами.
        """
        for first in first_chars:
            for rest in itertools.product(self._charset, repeat=self._length - 1):
                yield first + "".join(rest)


class SequentialCracker:
    """Відповідає лише за послідовний (однопроцесний) перебір паролів."""

    def __init__(self, hasher, target_hash):
        self._hasher = hasher
        self._target_hash = target_hash

    def crack(self, generator):
        """Перебирає кандидатів generator, повертає (пароль, час у секундах).

        Якщо пароль не знайдено, перший елемент кортежу дорівнює None.
        """
        start = time.perf_counter()
        for candidate in generator.generate():
            if self._hasher.compute(candidate) == self._target_hash:
                return candidate, time.perf_counter() - start
        return None, time.perf_counter() - start


def _worker_search(args):
    """Функція-робітник одного процесу: перебирає свою частину простору паролів."""
    charset, length, first_chars, algorithm_name, target_hash = args
    generator = CandidateGenerator(charset, length)
    hasher = PasswordHasher(algorithm_name)
    for candidate in generator.generate_chunk(first_chars):
        if hasher.compute(candidate) == target_hash:
            return candidate
    return None


class ParallelCracker:
    """Відповідає лише за паралельний перебір паролів з використанням Pool."""

    def __init__(self, charset, length, algorithm_name, target_hash, n_processes):
        self._charset = charset
        self._length = length
        self._algorithm_name = algorithm_name
        self._target_hash = target_hash
        self._n_processes = n_processes

    def _split_first_chars(self):
        """Ділить перші символи charset на n_processes груп (по одній на процес)."""
        chunks = [[] for _ in range(self._n_processes)]
        for i, ch in enumerate(self._charset):
            chunks[i % self._n_processes].append(ch)
        return [c for c in chunks if c]

    def crack(self):
        """Запускає Pool із n_processes процесів; повертає (пароль, час у секундах).

        Щойно один із процесів знаходить пароль, пул завершує роботу інших
        процесів (pool.terminate()), не чекаючи їх завершення.
        """
        start = time.perf_counter()
        tasks = [
            (
                self._charset,
                self._length,
                chunk,
                self._algorithm_name,
                self._target_hash,
            )
            for chunk in self._split_first_chars()
        ]
        found = None
        with Pool(processes=self._n_processes) as pool:
            for result in pool.imap_unordered(_worker_search, tasks):
                if result is not None:
                    found = result
                    pool.terminate()
                    break
        return found, time.perf_counter() - start
