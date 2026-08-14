import os
import time

import pytest

from src.repositories.cache_repository import JsonCacheRepository


CACHE_KEY = "a" * 24


def test_cache_repository_saves_and_loads_json_atomically(tmp_path):
    repository = JsonCacheRepository(tmp_path)

    path = repository.save("stage", CACHE_KEY, {"value": [1, 2, 3]})

    assert repository.load("stage", CACHE_KEY) == {"value": [1, 2, 3]}
    assert path == tmp_path / "stage" / f"{CACHE_KEY}.json"
    assert not list(path.parent.glob("*.tmp"))


def test_cache_repository_ignores_stale_or_corrupt_entries(tmp_path):
    repository = JsonCacheRepository(tmp_path)
    path = repository.save("stage", CACHE_KEY, {"value": 1})
    old_timestamp = time.time() - 120
    os.utime(path, (old_timestamp, old_timestamp))

    assert repository.load("stage", CACHE_KEY, max_age_seconds=60) is None

    path.write_text("not json", encoding="utf-8")
    assert repository.load("stage", CACHE_KEY) is None


@pytest.mark.parametrize("namespace", ["../outside", "/tmp/outside"])
def test_cache_repository_rejects_unsafe_namespace(tmp_path, namespace):
    repository = JsonCacheRepository(tmp_path)

    with pytest.raises(ValueError, match="namespace"):
        repository.path_for(namespace, CACHE_KEY)


def test_cache_repository_rejects_non_hex_key(tmp_path):
    repository = JsonCacheRepository(tmp_path)

    with pytest.raises(ValueError, match="hexadecimal"):
        repository.path_for("stage", "../../secret")
