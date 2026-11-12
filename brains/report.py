"""Only promote hypotheses that the judge marked as reproduced."""
from .schemas import Hypothesis, JudgeResult

def build_report(hypotheses: list[Hypothesis], judge_results: list[JudgeResult]) -> str:
    """Separate judge-confirmed results from all unconfirmed hypotheses."""
    by_id = {result.hypothesis_id: result for result in judge_results}
    confirmed, unverified = [], []
    for hypothesis in hypotheses:
        result = by_id.get(hypothesis.id)
        (confirmed if result is not None and result.reproduced is True else unverified).append((hypothesis, result))
    lines = ["IDOR/BOLA Assessment Report", "", "Findings confirmed by judge", "-----------------------------"]
    if not confirmed:
        lines.append("No judge-confirmed findings.")
    for hypothesis, result in confirmed:
        lines.extend([
            f"- {hypothesis.id}: {hypothesis.endpoint.method} {hypothesis.endpoint.path}",
            f"  Rationale: {hypothesis.rationale}",
            f"  Judge notes: {result.notes or 'No notes supplied.'}",
            f"  Evidence: {result.evidence}",
        ])
    lines.extend(["", "Unverified / not reproduced", "---------------------------"])
    if not unverified:
        lines.append("None.")
    for hypothesis, result in unverified:
        reason = "No judge result was provided." if result is None else f"Judge did not reproduce this hypothesis. {result.notes}".strip()
        lines.append(f"- {hypothesis.id}: {hypothesis.endpoint.method} {hypothesis.endpoint.path} - {reason}")
    return "\n".join(lines)
