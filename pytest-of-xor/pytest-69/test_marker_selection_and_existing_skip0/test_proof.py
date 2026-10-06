import pytest
@pytest.mark.parametrize('value', [0, 1])
def test_proof(value): assert value in (0, 1)
@pytest.mark.skip(reason='existing skip')
def test_skip(): assert False