"""Stub for CONSUMES dependency ``job_evaluation`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, EvaluationArtifact, EvaluationPolicyPins, LogicalRow, RankingArtifact, VersionPin


async def evaluate_job(channel_id: str, row: LogicalRow, candidate_profile: ArtifactReference, policies: EvaluationPolicyPins, method: str) -> EvaluationArtifact:
    return EvaluationArtifact(evaluation_id="eval/%s" % row.row_id, score="eligible")


def rank_evaluations(channel_id: str, evaluations: tuple[EvaluationArtifact, ...], policy: VersionPin) -> RankingArtifact:
    return RankingArtifact(ranking_id="rank/%s" % policy.version, order=tuple(e.evaluation_id for e in evaluations))
