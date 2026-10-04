# test/test_cli.py
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Assuming CLI entrypoint in ada.py; use subprocess for testing
import subprocess


def test_cli_help():
    # Use direct path to ada.py instead of -m ada (avoids module issues)
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    # Check stderr for 'usage' since argparse may output to stderr in some envs
    output = result.stdout + result.stderr
    assert 'usage' in output.lower()

def test_cli_version():
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, '--version'], capture_output=True, text=True)
    assert result.returncode == 0
    output = result.stdout + result.stderr
    assert '0.1.0' in output  # Matches version in ada.py

def test_cli_basic_run():
    # Test basic run with missing files (should error gracefully)
    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    result = subprocess.run([sys.executable, ada_path, 'nonexistent.exe'], capture_output=True, text=True)
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

    ada_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ada.py')
    # Run in a scratch dir: a successful MZ parse resets 'analysis.db' in cwd
    # and must not clobber the repository's real analysis database.
    scratch = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            [sys.executable, ada_path, valid_dummy, '-s', invalid_idc],
            capture_output=True, text=True, cwd=scratch
        )
        assert result.returncode == 1, f"Expected exit 1, got {result.returncode}"
        output = result.stdout + result.stderr
        assert 'IDC' in output, "Should mention IDC error"
    finally:
        os.unlink(invalid_idc)
        os.unlink(valid_dummy)
