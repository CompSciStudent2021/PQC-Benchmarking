"""
Kyber (ML-KEM) Key Generation Validation Script
-------------------------------------------------
This script checks that the installed post-quantum cryptography package(s)
can successfully perform Kyber/ML-KEM key generation, encapsulation, and
decapsulation, and that the shared secrets on both sides match.

Supports two common libraries (auto-detected):
  1. liboqs-python (import oqs)          -> pip install liboqs-python
  2. pqcrypto (import pqcrypto.kem...)   -> pip install pqcrypto

Run:
    python kyber_validation.py
"""

import sys
import traceback


def print_header(title: str) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def _print_liboqs_setup_help(exc: Exception) -> None:
    print(f"[!] liboqs-python could not load the native liboqs library: {exc}")
    print("    This typically happens because liboqs-python tries to build")
    print("    liboqs from source automatically, but 'cmake' is not on PATH.")
    print()
    print("    Option A - Install CMake, then reinstall liboqs-python:")
    print("      winget install Kitware.CMake")
    print("      (restart your terminal so PATH updates take effect)")
    print("      pip install --force-reinstall --no-cache-dir liboqs-python")
    print()
    print("    Option B - Skip liboqs-python and rely on 'pqcrypto' instead:")
    print("      pip install pqcrypto")
    print("      (this script automatically falls back to testing pqcrypto)")


def validate_with_liboqs() -> bool:
    """Attempt validation using liboqs-python (import oqs)."""
    try:
        import oqs
    except ImportError:
        return False
    except Exception as exc:
        print_header("Testing with liboqs-python (oqs)")
        _print_liboqs_setup_help(exc)
        return False

    print_header("Testing with liboqs-python (oqs)")

    # Common Kyber / ML-KEM algorithm names supported by liboqs
    candidate_algs = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "Kyber512",
        "Kyber768",
        "Kyber1024",
    ]

    try:
        available = oqs.get_enabled_kem_mechanisms()
    except Exception as exc:
        _print_liboqs_setup_help(exc)
        return False

    tested_any = False

    for alg in candidate_algs:
        if alg not in available:
            continue

        tested_any = True
        print(f"\n[+] Algorithm: {alg}")

        try:
            with oqs.KeyEncapsulation(alg) as client:
                public_key = client.generate_keypair()
                print(f"    Public key length:  {len(public_key)} bytes")

                with oqs.KeyEncapsulation(alg) as server:
                    ciphertext, shared_secret_server = server.encap_secret(public_key)
                    shared_secret_client = client.decap_secret(ciphertext)

                print(f"    Ciphertext length:  {len(ciphertext)} bytes")
                print(f"    Shared secret size:  {len(shared_secret_client)} bytes")

                if shared_secret_client == shared_secret_server:
                    print("    [PASS] Shared secrets match.")
                else:
                    print("    [FAIL] Shared secrets DO NOT match!")
                    return False
        except (RuntimeError, OSError) as exc:
            _print_liboqs_setup_help(exc)
            return False
        except Exception as exc:
            print(f"    [ERROR] {alg} failed: {exc}")
            return False

    if not tested_any:
        print("[!] No Kyber/ML-KEM mechanisms available in this liboqs build.")
        return False

    return True


def validate_with_pqcrypto() -> bool:
    """Attempt validation using the pqcrypto package."""
    modules_to_try = [
        ("pqcrypto.kem.ml_kem_512", "ML-KEM-512"),
        ("pqcrypto.kem.ml_kem_768", "ML-KEM-768"),
        ("pqcrypto.kem.ml_kem_1024", "ML-KEM-1024"),
        ("pqcrypto.kem.kyber512", "Kyber512"),
        ("pqcrypto.kem.kyber768", "Kyber768"),
        ("pqcrypto.kem.kyber1024", "Kyber1024"),
    ]

    import importlib

    any_module_found = False

    for module_name, display_name in modules_to_try:
        try:
            kem = importlib.import_module(module_name)
        except ImportError:
            continue

        any_module_found = True
        print_header(f"Testing with pqcrypto ({display_name})")

        try:
            public_key, secret_key = kem.generate_keypair()
            print(f"    Public key length: {len(public_key)} bytes")
            print(f"    Secret key length: {len(secret_key)} bytes")

            ciphertext, shared_secret_enc = kem.encrypt(public_key)
            shared_secret_dec = kem.decrypt(secret_key, ciphertext)

            print(f"    Ciphertext length: {len(ciphertext)} bytes")
            print(f"    Shared secret size: {len(shared_secret_dec)} bytes")

            if shared_secret_enc == shared_secret_dec:
                print("    [PASS] Shared secrets match.")
            else:
                print("    [FAIL] Shared secrets DO NOT match!")
                return False
        except Exception as exc:
            print(f"    [ERROR] {display_name} failed: {exc}")
            return False

    return any_module_found


def main() -> int:
    print_header("Kyber / ML-KEM Package Validation")
    print(f"Python version: {sys.version}")

    liboqs_ok = False
    pqcrypto_ok = False

    try:
        liboqs_ok = validate_with_liboqs()
    except Exception:
        print("[ERROR] Unexpected failure while testing liboqs-python:")
        traceback.print_exc()

    try:
        pqcrypto_ok = validate_with_pqcrypto()
    except Exception:
        print("[ERROR] Unexpected failure while testing pqcrypto:")
        traceback.print_exc()

    print_header("Summary")

    if not liboqs_ok and not pqcrypto_ok:
        print("[FAIL] No supported Kyber/ML-KEM library was detected or all tests failed.")
        print("       Try installing one of the following:")
        print("         pip install liboqs-python")
        print("         pip install pqcrypto")
        return 1

    if liboqs_ok:
        print("[PASS] liboqs-python Kyber/ML-KEM key generation validated successfully.")
    if pqcrypto_ok:
        print("[PASS] pqcrypto Kyber/ML-KEM key generation validated successfully.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
