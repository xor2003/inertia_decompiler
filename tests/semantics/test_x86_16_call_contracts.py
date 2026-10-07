from inertia.semantics.call_contracts import (
    RuntimeCallSemanticId8616,
    runtime_call_return_contract_8616,
)


def test_runtime_call_return_contract_proves_rand_nonnegative() -> None:
    contract = runtime_call_return_contract_8616("_rand")

    assert contract is not None
    assert contract.semantic_id is RuntimeCallSemanticId8616.C_RAND
    assert contract.value_range.is_nonnegative


def test_runtime_call_return_contract_refuses_unknown_identity() -> None:
    assert runtime_call_return_contract_8616("sub_1234") is None
    assert runtime_call_return_contract_8616(None) is None
