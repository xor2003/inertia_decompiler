"""The public retry seam serializes cutpoint search accounting as JSON."""

import json
from dataclasses import asdict

from tools.dosunit.paired_region_graph import RegionExitKind, RegionNode
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_region_proof import RegionProof, RegionProofReason
from tools.dosunit.region_pairing import propose_region_pairings


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
