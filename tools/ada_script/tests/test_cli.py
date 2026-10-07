# test/test_cli.py
import os

# Exercise the supported package command in a fresh process.
import subprocess
import sys
import tempfile
from pathlib import Path


def test_cli_help():
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    # Check stderr for 'usage' since argparse may output to stderr in some envs
    output = result.stdout + result.stderr
    assert 'usage' in output.lower()

def test_cli_version():
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", '--version'], capture_output=True, text=True)
    assert result.returncode == 0
    output = result.stdout + result.stderr
    assert '0.1.0' in output  # Matches the integrated CLI version

def test_cli_basic_run():
    # Test basic run with missing files (should error gracefully)
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", 'nonexistent.exe'], capture_output=True, text=True)
    assert result.returncode == 1  # Expected error exit
    assert 'Binary not found' in (result.stdout + result.stderr)

def test_cli_idc_failure():
    """Test that IDC parsing failure exits with non-zero code."""
    # Create invalid IDC
    with tempfile.NamedTemporaryFile(suffix='.idc', delete=False) as f:
        f.write(b'invalid syntax here;')  # Causes Lark parse error
        invalid_idc = f.name

    # Create minimal valid MZ dummy (64 bytes to pass len check)
    mz_header = b'MZ' + b'\x00' * 62  # Pad to 64 bytes; unpacks succeed
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(mz_header)
        valid_dummy = f.name

    # Run in a scratch dir: a successful MZ parse resets 'analysis.db' in cwd
    # and must not clobber the repository's real analysis database.
    scratch = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "tools.ada_script", valid_dummy, '-s', invalid_idc, "--work-dir", scratch, "--no-signatures"],
            capture_output=True, text=True, cwd=Path(__file__).resolve().parents[3]
        )
        assert result.returncode == 1, f"Expected exit 1, got {result.returncode}"
        output = result.stdout + result.stderr
        assert 'IDC' in output, "Should mention IDC error"
    finally:
        os.unlink(invalid_idc)
        os.unlink(valid_dummy)
