"""T-17: development trust profile (API.md §C profile.py, §A, §E; D-016; SR-1 (i))."""

from __future__ import annotations

from teecustody_sim import launch_config_hashes


def test_launch_config_hashes_are_sha256_of_canonical_cbor_args_and_env() -> None:
    args_hash, env_hash = launch_config_hashes(["/app/workload"], [("PYTHONUNBUFFERED", "1")])

    assert args_hash == "0d7b8d1aa29f148b5f78df8a6214175db1991281625e7727ce2ca5945f090c99"
    assert env_hash == "942fabd2e68b234f374ade89d81e9adf3414e9603216bb66b8252ceff35f3ecb"
