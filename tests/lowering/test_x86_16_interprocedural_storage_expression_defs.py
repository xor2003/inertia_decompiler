from __future__ import annotations

import pytest
from inertia.semantics.callsite_summary import (
    CallsitePushExprOp8616,
    CallsitePushSourceKind8616,
)
from inertia.ir import SSAFunctionArtifact
from inertia.lowering.interprocedural_storage_expression_defs import (
    resolve_expression_argument_definitions_8616,
)
from inertia.lowering.interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    PhysicalCallArgumentPiece8616,
)

BP_VALUE = CallsitePushSourceKind8616.BP_VALUE.value
EXPR = CallsitePushSourceKind8616.EXPR.value


@pytest.mark.parametrize(
    ("source", "failure"),
    (
        (
            (EXPR, (BP_VALUE, -2, 2), ((CallsitePushExprOp8616.ADC.value, 1),)),
            CallArgumentDefinitionFailure8616.EXPRESSION_FLAGS_UNPROVEN,
        ),
        (
            (EXPR, (BP_VALUE, -2, 2), ((CallsitePushExprOp8616.SHL.value, 16),)),
            CallArgumentDefinitionFailure8616.EXPRESSION_WIDTH_CONFLICT,
        ),
        (
            (EXPR, (BP_VALUE, -2, 2), ((CallsitePushExprOp8616.XOR.value, 1),)),
            CallArgumentDefinitionFailure8616.EXPRESSION_OPERATION_UNSUPPORTED,
        ),
        (
            (EXPR, (BP_VALUE, -2, 2), ("not-an-operation",)),
            CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT,
        ),
    ),
)
def test_expression_sources_refuse_unsupported_or_unproven_semantics(
    source: tuple[object, ...],
    failure: CallArgumentDefinitionFailure8616,
) -> None:
    definitions, expression, observed_failure = (
        resolve_expression_argument_definitions_8616(
            SSAFunctionArtifact(0x1000, ()),
            (),
            PhysicalCallArgumentPiece8616(2, source, 0x1010),
        )
    )

    assert definitions is None
    assert expression is None
    assert observed_failure is failure
