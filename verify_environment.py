"""
Environment Verification Script - Dissertation PoC
----------------------------------------------------
Verifies that all required Python packages for the post-quantum cryptography
proof-of-concept are installed and functioning correctly. This is
VERIFICATION ONLY -- no benchmarking or comparison framework is implemented
yet.

Libraries verified:
  - kyber-py      : Kyber / ML-KEM reference implementation (key generation)
  - dilithium-py  : ML-DSA / Dilithium reference implementation (key generation)
  - pycryptodome  : classical cryptographic primitives (comparison baseline)
  - cryptography  : general cryptographic primitives
  - timeit / time : benchmarking utilities (standard library)
  - numpy / pandas: numerical + tabular data handling
  - matplotlib    : visualisation

Run:
    python verify_environment.py
"""

import sys
import importlib
import traceback

# Number of leading bytes shown when previewing a generated key. Kept short
# so large ML-KEM-1024 / ML-DSA-87 keys stay readable in the console output.
KEY_PREVIEW_BYTES = 32


def print_header(title: str) -> None:
    """Print a visually distinct section header to separate check groups."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def check_import(module_name: str, friendly_name: str = None) -> bool:
    """
    Import a module by name and report success/failure plus its version.

    Lightweight "is this package installed at all" check, run before any
    functional (behavioural) test against the same library.
    """
    friendly_name = friendly_name or module_name
    try:
        module = importlib.import_module(module_name)
        version = getattr(module, "__version__", "unknown")
        print(f"[PASS] {friendly_name} imported (version: {version})")
        return True
    except ImportError as exc:
        print(f"[FAIL] {friendly_name} failed to import: {exc}")
        return False


def _hex_preview(data: bytes, preview_len: int = KEY_PREVIEW_BYTES) -> str:
    """
    Return a readable hex preview of key bytes.

    Full key material can be hundreds of bytes at the higher security
    levels, so long keys are truncated with the total byte count noted
    instead of flooding the console.
    """
    if len(data) <= preview_len:
        return data.hex()
    return f"{data[:preview_len].hex()}... (truncated, {len(data)} bytes total)"


def _import_kyber_schemes():
    """
    Import Kyber/ML-KEM classes from kyber-py.

    Supports both the modern FIPS 203 naming (ML_KEM_512/768/1024) and the
    legacy round-3 naming (Kyber512/768/1024). The modern name is tried
    first since it matches the finalised NIST standard.
    """
    try:
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

        return [
            ("ML-KEM-512", ML_KEM_512),
            ("ML-KEM-768", ML_KEM_768),
            ("ML-KEM-1024", ML_KEM_1024),
        ]
    except ImportError:
        pass  # fall back to legacy naming below

    from kyber_py.kyber import Kyber512, Kyber768, Kyber1024

    return [
        ("Kyber512", Kyber512),
        ("Kyber768", Kyber768),
        ("Kyber1024", Kyber1024),
    ]


def _import_ml_dsa_schemes():
    """
    Import ML-DSA/Dilithium classes from dilithium-py.

    Supports both the modern FIPS 204 naming (ML_DSA_44/65/87) and the
    legacy naming (Dilithium2/3/5). The modern name is tried first since
    it matches the finalised NIST standard.
    """
    try:
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

        return [
            ("ML-DSA-44", ML_DSA_44),
            ("ML-DSA-65", ML_DSA_65),
            ("ML-DSA-87", ML_DSA_87),
        ]
    except ImportError:
        pass  # fall back to legacy naming below

    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

    return [
        ("Dilithium2", Dilithium2),
        ("Dilithium3", Dilithium3),
        ("Dilithium5", Dilithium5),
    ]


def _run_keygen_verification(
    library_display_name: str,
    pip_package: str,
    import_schemes_fn,
    key_labels: tuple,
) -> bool:
    """
    Shared verification routine for a PQC reference-implementation library.

    kyber-py (KEM) and dilithium-py (signatures) both expose scheme objects
    with a parameterless keygen() returning a (key_a, key_b) tuple, so this
    single routine replaces what used to be two near-identical functions
    with duplicated loop/print logic.

    Args:
        library_display_name: Name shown in the section header/log lines.
        pip_package: Package name suggested in the install hint on failure.
        import_schemes_fn: Callable returning a list of (name, scheme)
            tuples, one per security level.
        key_labels: Two-item tuple naming the values keygen() returns,
            e.g. ("Public (ek)", "Private (dk)").

    Returns:
        True if every security level generated keys successfully.
    """
    print_header(f"{library_display_name}: Key Generation (all security levels)")

    try:
        levels = import_schemes_fn()
    except ImportError as exc:
        print(f"[FAIL] {library_display_name} failed to import: {exc}")
        print(f"       Install it with: pip install {pip_package}")
        return False

    all_ok = True
    label_a, label_b = key_labels

    for name, scheme in levels:
        try:
            key_a, key_b = scheme.keygen()
            # Sizes first (quick sanity check), then hex previews so you can
            # visually confirm distinct, real key material at each level.
            print(
                f"[PASS] {name} keygen() succeeded "
                f"({label_a}: {len(key_a)} bytes, {label_b}: {len(key_b)} bytes)"
            )
            print(f"       {label_a} key: {_hex_preview(key_a)}")
            print(f"       {label_b} key: {_hex_preview(key_b)}")
        except Exception as exc:
            print(f"[FAIL] {name} keygen() failed: {exc}")
            traceback.print_exc()
            all_ok = False

    return all_ok


def verify_kyber_py() -> bool:
    """Run basic key generation with kyber-py at all three security levels."""
    return _run_keygen_verification(
        library_display_name="kyber-py (Kyber/ML-KEM)",
        pip_package="kyber-py",
        import_schemes_fn=_import_kyber_schemes,
        key_labels=("Public (ek)", "Private (dk)"),
    )


def verify_ml_dsa_py() -> bool:
    """Run basic key generation with dilithium-py at all three security levels."""
    return _run_keygen_verification(
        library_display_name="dilithium-py (ML-DSA/Dilithium)",
        pip_package="dilithium-py",
        import_schemes_fn=_import_ml_dsa_schemes,
        key_labels=("Public (pk)", "Secret (sk)"),
    )


def verify_classical_crypto() -> bool:
    """Verify pycryptodome and cryptography are installed and functional."""
    print_header("pycryptodome + cryptography: Classical Primitives")

    # Step 1: confirm both packages are importable at all.
    ok = True
    ok &= check_import("Crypto", "pycryptodome (Crypto)")
    ok &= check_import("cryptography")

    # Step 2: functional check for pycryptodome -- a full AES-EAX
    # encrypt/digest round trip, not just an import.
    try:
        from Crypto.Random import get_random_bytes
        from Crypto.Cipher import AES

        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_EAX)
        cipher.encrypt_and_digest(b"pycryptodome environment check")
        print("[PASS] pycryptodome AES encryption round-trip succeeded.")
    except Exception as exc:
        print(f"[FAIL] pycryptodome functional check failed: {exc}")
        ok = False

    # Step 3: functional check for cryptography -- RSA key generation.
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Small key size purely for a fast sanity check, not for security use.
        rsa.generate_private_key(public_exponent=65537, key_size=1024)
        print("[PASS] cryptography RSA key generation succeeded.")
    except Exception as exc:
        print(f"[FAIL] cryptography functional check failed: {exc}")
        ok = False

    return ok


def verify_benchmarking_utils() -> bool:
    """Verify timeit and time are usable (standard library, no install needed)."""
    print_header("timeit / time: Benchmarking Utilities")
    try:
        import time
        import timeit

        # Time a trivial timeit run to prove both modules cooperate; the
        # duration itself is irrelevant here, only that no exception occurs.
        start = time.perf_counter()
        timeit.timeit("pass", number=1000)
        elapsed = time.perf_counter() - start
        print(f"[PASS] timeit + time executed correctly (sample run: {elapsed:.6f}s)")
        return True
    except Exception as exc:
        print(f"[FAIL] timeit/time verification failed: {exc}")
        return False


def verify_data_libraries() -> bool:
    """Verify numpy and pandas are installed and functional."""
    print_header("numpy / pandas: Data Handling")

    ok = True
    ok &= check_import("numpy")
    ok &= check_import("pandas")

    # Functional check: build an ndarray, feed it into a DataFrame, confirm
    # the two libraries interoperate as they will during benchmarking.
    try:
        import numpy as np
        import pandas as pd

        arr = np.array([1, 2, 3, 4, 5])
        df = pd.DataFrame({"value": arr, "squared": arr ** 2})
        print(f"[PASS] numpy array created and pandas DataFrame built ({len(df)} rows).")
    except Exception as exc:
        print(f"[FAIL] numpy/pandas functional check failed: {exc}")
        ok = False

    return ok


def verify_visualisation() -> bool:
    """Verify matplotlib is installed and can render a figure."""
    print_header("matplotlib: Visualisation")
    ok = check_import("matplotlib")

    try:
        import matplotlib

        # "Agg" is a non-interactive, image-only backend -- safe on headless
        # machines/CI where no display server is available.
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots()
        ax.plot([0, 1, 2], [0, 1, 4])
        plt.close(fig)  # release the figure immediately; this is a smoke test only
        print("[PASS] matplotlib figure created and closed without error.")
    except Exception as exc:
        print(f"[FAIL] matplotlib functional check failed: {exc}")
        ok = False

    return ok


def main() -> int:
    """Run every library check and print a final pass/fail summary."""
    print_header("Dissertation PoC - Environment Verification (No Build Yet)")
    print(f"Python version: {sys.version}")

    # Each entry: human-readable label -> True/False result of that check.
    results = {
        "kyber-py (Kyber/ML-KEM keygen, 3 levels)": verify_kyber_py(),
        "dilithium-py (ML-DSA/Dilithium keygen, 3 levels)": verify_ml_dsa_py(),
        "pycryptodome / cryptography": verify_classical_crypto(),
        "timeit / time": verify_benchmarking_utils(),
        "numpy / pandas": verify_data_libraries(),
        "matplotlib": verify_visualisation(),
    }

    print_header("Summary")
    for label, passed in results.items():
        print(f"[{'PASS' if passed else 'FAIL'}] {label}")

    if all(results.values()):
        print("\nAll libraries verified successfully. Environment is ready.")
        return 0

    print("\nOne or more libraries failed verification. See details above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
