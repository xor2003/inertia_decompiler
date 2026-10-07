from inertia.postprocess.call_argument_transaction import (
    CallArgumentMutationVerdict8616,
    accepted_call_argument_mutation_8616,
    refused_call_argument_mutation_8616,
)


def test_accepted_call_argument_mutation_allows_setup_consumption():
    result = accepted_call_argument_mutation_8616(
        arguments_changed=True,
        target_changed=False,
    )

    assert result.verdict is CallArgumentMutationVerdict8616.APPLIED
    assert result.arguments_accepted is True
    assert result.changed is True


def test_unchanged_call_argument_mutation_remains_accepted():
    result = accepted_call_argument_mutation_8616(
        arguments_changed=False,
        target_changed=False,
    )

    assert result.verdict is CallArgumentMutationVerdict8616.UNCHANGED
    assert result.arguments_accepted is True
    assert result.changed is False


def test_refused_call_argument_mutation_blocks_setup_consumption_but_reports_independent_change():
    result = refused_call_argument_mutation_8616(
        arguments_changed=False,
        target_changed=True,
    )

    assert result.verdict is CallArgumentMutationVerdict8616.REFUSED
    assert result.arguments_accepted is False
    assert result.changed is True
