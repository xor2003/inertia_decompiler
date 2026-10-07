"""Layer: test support.
Responsibility: expose the bounded capture-vector fixture API to regressions.
"""
from tests.fixtures.replay_capture_contracts_test_support import (
    CaptureWindow as CaptureWindow,
)
from tests.fixtures.replay_capture_contracts_test_support import (
    WindowAdmissionKind as WindowAdmissionKind,
)
from tests.fixtures.replay_capture_contracts_test_support import (
    WindowRole as WindowRole,
)
from tests.fixtures.replay_capture_contracts_test_support import (
    flat32_declared_extents as flat32_declared_extents,
)
from tests.fixtures.replay_capture_emission_test_support import (
    emit_flat32 as emit_flat32,
)
from tests.fixtures.replay_capture_emission_test_support import (
    emit_real16 as emit_real16,
)
from tests.fixtures.replay_capture_experiment_test_support import (
    build_accounting as build_accounting,
)
from tests.fixtures.replay_capture_experiment_test_support import (
    run_experiment as run_experiment,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    _F32_MUT_OFFSET as _F32_MUT_OFFSET,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    _R16_MUT_OFFSET as _R16_MUT_OFFSET,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    F32_ESP as F32_ESP,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    MAX_COHORT_VECTORS as MAX_COHORT_VECTORS,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_ARRAY as R16_ARRAY,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_CALLEE as R16_CALLEE,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_LOAD as R16_LOAD,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_SP as R16_SP,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_SPIN as R16_SPIN,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_SS as R16_SS,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    R16_TRAP_OFF as R16_TRAP_OFF,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    SEED as SEED,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    flat32_code_bytes as flat32_code_bytes,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    flat32_data_bytes as flat32_data_bytes,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    flat32_pe_image as flat32_pe_image,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    real16_image_bytes as real16_image_bytes,
)
from tests.fixtures.replay_capture_fixture_test_support import (
    real16_load_image as real16_load_image,
)
from tests.fixtures.replay_capture_setup_test_support import (
    F32_CAPTURE_WINDOWS as F32_CAPTURE_WINDOWS,
)
from tests.fixtures.replay_capture_setup_test_support import (
    R16_CAPTURE_WINDOWS as R16_CAPTURE_WINDOWS,
)
from tests.fixtures.replay_capture_setup_test_support import (
    capture_flat32 as capture_flat32,
)
from tests.fixtures.replay_capture_setup_test_support import (
    capture_real16 as capture_real16,
)
from tests.fixtures.replay_capture_setup_test_support import (
    flat32_capture_fixture as flat32_capture_fixture,
)
from tests.fixtures.replay_capture_setup_test_support import (
    real16_capture_fixture as real16_capture_fixture,
)
from tests.fixtures.replay_capture_windows_test_support import (
    flat32_window_check as flat32_window_check,
)
from tests.fixtures.replay_capture_windows_test_support import (
    real16_window_check as real16_window_check,
)

from tools.dosunit.runtime.replay_capture_model import CaptureStatus as CaptureStatus
