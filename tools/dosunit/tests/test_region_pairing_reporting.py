"""The public retry seam serializes cutpoint search accounting as JSON."""

import json
from dataclasses import asdict

from tools.dosunit.compare.paired_region_graph import RegionExitKind, RegionNode
from tools.dosunit.compare.real16_region_proof import RegionProof, RegionProofReason
from tools.dosunit.compare.region_pairing import propose_region_pairings
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus


def test_search_accounting_survives_public_json_report() -> None:
    """Rejected/proposed covers must remain usable in a written public report."""
    nodes = {
        0: RegionNode(0, (1, 2), RegionExitKind.BORING),
        1: RegionNode(1, (0,), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    search = propose_region_pairings(nodes, nodes, 0, 0, deadline_seconds=1)
    proof = RegionProof(ProofStatus.UNKNOWN, RegionProofReason.GRAPH, (),
                        FactCounters(1, 1, 1, 1, 1), graph_search=search.evidence())
    restored = json.loads(json.dumps(asdict(proof), sort_keys=True))
    assert restored["graph_search"]["candidates"]
    assert restored["graph_search"]["searches"]



def test_relaxed_search_reuses_identical_transition_obligations() -> None:
    """Relaxing injectivity must not charge identical candidate checks twice."""
    import time

    from tools.dosunit.compare.flat32_loop_graph_search import search_loop_graphs
    from tools.dosunit.compare.region_pairing import PairedRegions

    nodes = {
        0: RegionNode(0, (1, 2), RegionExitKind.BORING),
        1: RegionNode(1, (1, 2), RegionExitKind.BORING),
        2: RegionNode(2, (), RegionExitKind.RETURN),
    }
    checks: list[tuple[str, frozenset[tuple[int, int]]]] = []

    def reject(graph: PairedRegions) -> dict[str, object]:
        """Record real obligation identities without pretending to prove them."""
        checks.append((graph.evidence.formation.value, frozenset(graph.pairs)))
        return {"status": "refused", "reason": "test_transition_unproved"}

    result = search_loop_graphs(nodes, nodes, 0, 0, reject, deadline=time.monotonic() + 10, name="root")
    assert result["status"] == "refused"
    assert checks and len(checks) == len(set(checks))
    assert result["strict_graph_search"]
    assert result["state_merge_graph_search"]
