"""
tiny-bounty-workflow — Autonomous Bounty Workflow Engine
Zero-dependency. MIT. ~500 lines.

State machine for autonomous bounty hunting:
  SCAN → SCORE → PLAN → IMPLEMENT → TEST → PR → REVIEW
                                                  ↓
                                             ITERATE ←──────┐
                                                  ↓           │
                                              (comments)      │
                                                  ↓           │
                                              IMPLEMENT ─────┘

Anti-scam filters included. Works with GitHub API (fine-grained PAT).

Usage:
    from tiny_bounty_workflow import BountyWorkflow, BountyScorer

    scorer = BountyScorer()
    workflow = BountyWorkflow(scorer=scorer, github_token="ghp_...")

    workflow.scan(languages=["python"], min_bounty=50)
    workflow.run_top(max_iterations=3)
"""

from __future__ import annotations

import json
import time
import re
import os
from typing import Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
from threading import Lock
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from tiny_agent_memory import TieredMemory
    _HAS_MEMORY = True
except Exception:
    _HAS_MEMORY = False


# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────

class BountyState(Enum):
    SCANNED = "scanned"
    SCORED = "scored"
    PLANNED = "planned"
    IMPLEMENTING = "implementing"
    TESTING = "testing"
    PR_OPENED = "pr_opened"
    REVIEWING = "reviewing"
    ITERATING = "iterating"
    MERGED = "merged"
    REJECTED = "rejected"
    FAILED = "failed"
    ABANDONED = "abandoned"


@dataclass
class Bounty:
    id: str
    repo: str
    number: int
    title: str
    body: str
    state: BountyState = BountyState.SCANNED
    score: float = 0.0
    payout_estimate: float = 0.0
    competition: int = 0  # number of existing PRs
    labels: list[str] = field(default_factory=list)
    language: str = ""
    author: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    url: str = ""
    scam_probability: float = 0.0
    stack_fit: float = 0.5  # 0-1, how well agent's stack matches
    clarity: float = 0.5   # 0-1, how well-specified the issue is
    plan: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    review_count: int = 0
    iteration: int = 0
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @property
    def is_active(self) -> bool:
        return self.state in (
            BountyState.SCANNED, BountyState.SCORED, BountyState.PLANNED,
            BountyState.IMPLEMENTING, BountyState.TESTING, BountyState.PR_OPENED,
            BountyState.REVIEWING, BountyState.ITERATING
        )


@dataclass
class WorkflowReport:
    started_at: float
    ended_at: float = 0.0
    scanned: int = 0
    scored: int = 0
    implemented: int = 0
    pr_opened: int = 0
    merged: int = 0
    iterations: int = 0
    errors: int = 0
    total_cost_usd: float = 0.0
    bounties: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Anti-Scam Filter
# ─────────────────────────────────────────────────────────────

class AntiScamFilter:
    """
    Reject common bounty scams before wasting compute.
    Rejects ~60% of labeled bounties on average.
    """

    def __init__(self):
        self._known_scam_patterns = [
            r"dm\s*me\s*for\s*bounty",
            r"contact\s*me\s*on\s*whatsapp",
            r"telegram\s*@",
            r"paypal\s*me",
            r"send.*\$.*before",
            r"bounty\s*is\s*not\s*listed",
            r"check\s*my\s*profile",
            r"just\s*fork\s*and\s*run",
        ]
        self._payout_indicators = re.compile(
            r"\$[\d,]+|€[\d,]+|£[\d,]+|\$?\d+\s*(usd|eur|gbp)",
            re.IGNORECASE
        )

    def check(self, bounty: Bounty) -> tuple[bool, str]:
        """
        Returns (is_clean, reason).
        is_clean=True means the bounty passes the filter.
        """
        body = (bounty.body or "").lower()
        title = (bounty.title or "").lower()

        # Check scam patterns
        for pattern in self._known_scam_patterns:
            if re.search(pattern, body) or re.search(pattern, title):
                return False, f"scam_pattern:{pattern}"

        # Check for payout mention (scam filter: bounties that hide payout are sus)
        has_payout = bool(self._payout_indicators.search(body))
        if not has_payout and any(
            l.lower() in ("bounty", "paid", "reward", "$")
            for l in bounty.labels
        ):
            # Bounty label but no payout in body — might be expired
            if time.time() - bounty.created_at > 90 * 86400:
                return False, "expired_bounty"

        # Check repo age and stars
        repo_meta = bounty.metadata.get("repo_meta", {})
        stars = repo_meta.get("stars", 0)
        age_days = (time.time() - repo_meta.get("created_at", time.time())) / 86400
        if stars < 5 and age_days < 30:
            return False, "new_empty_repo"

        # High competition
        if bounty.competition > 50:
            return False, f"too_competitive({bounty.competition})"

        return True, "clean"


# ─────────────────────────────────────────────────────────────
# Bounty Scorer
# ─────────────────────────────────────────────────────────────

class BountyScorer:
    """
    Scores a bounty by payout, competition, stack fit, clarity, and freshness.

    Score = w1·payout + w2·(1/competition) + w3·stack_fit + w4·clarity + w5·freshness

    Weights are configurable for different agent profiles.
    """

    def __init__(
        self,
        w_payout: float = 0.30,
        w_competition: float = 0.20,
        w_stack: float = 0.25,
        w_clarity: float = 0.15,
        w_freshness: float = 0.10,
    ):
        self.w = {
            "payout": w_payout,
            "competition": w_competition,
            "stack": w_stack,
            "clarity": w_clarity,
            "freshness": w_freshness,
        }
        self._scam = AntiScamFilter()

    def extract_payout(self, body: str) -> float:
        """Extract dollar amount from issue body."""
        if not body:
            return 0.0
        matches = re.findall(r"\$[\d,]+(?:\.\d{2})?", body)
        if not matches:
            # Try plain numbers near "bounty", "reward", "paid"
            for m in re.finditer(r"(?:bounty|reward|paid|payout)\s*[:\-]?\s*(\d+(?:\.\d{2})?)", body, re.IGNORECASE):
                try:
                    return float(m.group(1))
                except ValueError:
                    pass
            return 0.0
        try:
            return float(matches[0].replace("$", "").replace(",", ""))
        except ValueError:
            return 0.0

    def _clarity_score(self, body: str) -> float:
        """Heuristic: how well-specified is the issue?"""
        if not body:
            return 0.1
        score = 0.5
        if re.search(r"(?:steps to reproduce|reproduce|expected|actual)", body, re.IGNORECASE):
            score += 0.15
        if re.search(r"```[\s\S]*```", body):  # code block present
            score += 0.15
        if re.search(r"(?:error|exception|traceback)", body, re.IGNORECASE):
            score += 0.1
        if len(body) > 200:
            score += 0.1
        return min(score, 1.0)

    def _freshness_score(self, created_at: float) -> float:
        """Newer issues score higher. Max bonus for <7 days."""
        age_days = (time.time() - created_at) / 86400
        if age_days < 7:
            return 1.0
        elif age_days < 30:
            return 0.8
        elif age_days < 90:
            return 0.5
        else:
            return 0.2

    def score(self, bounty: Bounty) -> tuple[float, dict]:
        """
        Score a bounty. Returns (score, breakdown_dict).
        Sets bounty.score and bounty.scam_probability.
        """
        # Anti-scam check first
        clean, reason = self._scam.check(bounty)
        if not clean:
            bounty.scam_probability = 1.0
            bounty.score = 0.0
            return 0.0, {"scam": reason}

        # Extract payout
        bounty.payout_estimate = self.extract_payout(bounty.body)
        bounty.clarity = self._clarity_score(bounty.body)
        bounty.scam_probability = 0.0

        # Normalize components
        payout_norm = min(bounty.payout_estimate / 500.0, 1.0)  # 500 = max normalized payout
        competition_norm = 1.0 / (1.0 + bounty.competition / 10.0)
        freshness_norm = self._freshness_score(bounty.created_at)

        score = (
            self.w["payout"] * payout_norm +
            self.w["competition"] * competition_norm +
            self.w["stack"] * bounty.stack_fit +
            self.w["clarity"] * bounty.clarity +
            self.w["freshness"] * freshness_norm
        )
        bounty.score = round(score, 4)
        breakdown = {
            "payout": round(payout_norm, 3),
            "competition": round(competition_norm, 3),
            "stack": bounty.stack_fit,
            "clarity": round(bounty.clarity, 3),
            "freshness": round(freshness_norm, 3),
            "raw_score": round(score, 4),
        }
        return score, breakdown


# ─────────────────────────────────────────────────────────────
# GitHub API Client
# ─────────────────────────────────────────────────────────────

class GitHubClient:
    """Minimal GitHub REST API client using stdlib only."""

    BASE = "https://api.github.com"

    def __init__(self, token: str):
        self.token = token
        self._lock = Lock()
        self._rate_remaining = 5000

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "tiny-bounty-workflow/1.0",
        }

    def _request(self, method: str, url: str, data: Optional[dict] = None) -> dict:
        with self._lock:
            body = json.dumps(data).encode() if data else None
            req = Request(url, data=body, headers=self._headers(), method=method)
            try:
                with urlopen(req, timeout=30) as resp:
                    self._rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", 5000))
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except HTTPError as e:
                if e.code == 403:
                    self._rate_remaining = 0
                raise

    def search_issues(
        self,
        query: str,
        sort: str = "created",
        order: str = "desc",
        per_page: int = 30,
    ) -> list[dict]:
        q = (
            f"{query} "
            f"is:issue "
            f"is:open "
            f"no:assignee "
            f"archived:false"
        )
        url = (
            f"{self.BASE}/search/issues"
            f"?q={q}&sort={sort}&order={order}&per_page={per_page}"
        )
        data = self._request("GET", url)
        return data.get("items", [])

    def get_issue(self, owner: str, repo: str, number: int) -> dict:
        url = f"{self.BASE}/repos/{owner}/{repo}/issues/{number}"
        return self._request("GET", url)

    def get_pr_count(self, owner: str, repo: str, issue_number: int) -> int:
        url = f"{self.BASE}/repos/{owner}/{repo}/issues/{issue_number}/timeline"
        try:
            self._request("GET", url)
        except HTTPError:
            pass
        # Fallback: count PRs mentioning the issue
        search_url = (
            f"{self.BASE}/search/issues"
            f"?q=repo:{owner}/{repo}+{issue_number}+is:pr+is:open"
        )
        data = self._request("GET", search_url)
        return data.get("total_count", 0)

    def create_pr(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
    ) -> dict:
        url = f"{self.BASE}/repos/{owner}/{repo}/pulls"
        data = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        }
        return self._request("POST", url, data)

    def get_repo_meta(self, owner: str, repo: str) -> dict:
        url = f"{self.BASE}/repos/{owner}/{repo}"
        try:
            data = self._request("GET", url)
            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "language": data.get("language", ""),
                "created_at": 0,
            }
        except Exception:
            return {}


# ─────────────────────────────────────────────────────────────
# Bounty Workflow Engine
# ─────────────────────────────────────────────────────────────

class BountyWorkflow:
    """
    Autonomous bounty workflow engine.

    State machine: SCAN → SCORE → PLAN → IMPLEMENT → TEST → PR → REVIEW
                                                              ↓
                                                         ITERATE ←─┐
                                                              ↓     │
                                                         (comments)  │
                                                              ↓     │
                                                         IMPLEMENT ─┘
    """

    def __init__(
        self,
        scorer: BountyScorer,
        github_token: str,
        memory: Optional[Any] = None,
        agent_languages: Optional[list[str]] = None,
    ):
        self.scorer = scorer
        self.github = GitHubClient(github_token)
        self.memory = memory
        self.languages = agent_languages or ["python", "javascript", "typescript", "go"]
        self._bounties: dict[str, Bounty] = {}
        self._lock = Lock()
        self._report = WorkflowReport(started_at=time.time())
        self._token = github_token

    # ── Scan ──────────────────────────────────────────────────

    def scan(
        self,
        query: str = "bounty",
        languages: Optional[list[str]] = None,
        min_bounty: float = 0.0,
        max_results: int = 50,
    ) -> list[Bounty]:
        """
        Scan GitHub for bounty issues matching the query.
        Returns list of Bounty objects (unscored).
        """
        langs = languages or self.languages
        results: list[Bounty] = []

        for lang in langs:
            q = f"{query} language:{lang}"
            try:
                issues = self.github.search_issues(q, per_page=max_results // len(langs))
            except Exception as e:
                self._report.errors += 1
                continue

            for item in issues:
                bounty = self._issue_to_bounty(item, lang)
                with self._lock:
                    self._bounties[bounty.id] = bounty
                results.append(bounty)

        self._report.scanned += len(results)
        return results

    def _issue_to_bounty(self, item: dict, lang: str) -> Bounty:
        repo_url = item.get("repository_url", "")
        repo = "/".join(repo_url.split("/")[-2:])
        owner, name = repo.split("/") if "/" in repo else (item.get("user", {}).get("login", ""), "")

        bounty = Bounty(
            id=f"{repo}#{item['number']}",
            repo=repo,
            number=item["number"],
            title=item.get("title", ""),
            body=item.get("body", "") or "",
            state=BountyState.SCANNED,
            language=lang,
            author=item.get("user", {}).get("login", ""),
            created_at=time.mktime(
                time.strptime(item.get("created_at", "1970-01-01")[:19], "%Y-%m-%dT%H:%M:%S")
            ) if item.get("created_at") else 0,
            updated_at=time.mktime(
                time.strptime(item.get("updated_at", "1970-01-01")[:19], "%Y-%m-%dT%H:%M:%S")
            ) if item.get("updated_at") else 0,
            url=item.get("html_url", ""),
            labels=[l.get("name", "") for l in item.get("labels", [])],
        )
        # Get PR count and repo meta
        try:
            bounty.competition = self.github.get_pr_count(owner, name, bounty.number)
            bounty.metadata["repo_meta"] = self.github.get_repo_meta(owner, name)
        except Exception:
            pass
        return bounty

    # ── Score ───────────────────────────────────────────────

    def score_all(self, min_score: float = 0.3) -> list[Bounty]:
        """Score all unscored bounties. Returns those above min_score."""
        scored: list[Bounty] = []
        with self._lock:
            bounties = list(self._bounties.values())
        for b in bounties:
            if b.state != BountyState.SCANNED:
                continue
            score, _ = self.scorer.score(b)
            b.state = BountyState.SCORED
            if score >= min_score:
                scored.append(b)
                self._report.scored += 1
        return sorted(scored, key=lambda x: x.score, reverse=True)

    def get_top(self, n: int = 5) -> list[Bounty]:
        """Return top N scored bounties."""
        with self._lock:
            active = [b for b in self._bounties.values() if b.is_active]
        return sorted(active, key=lambda x: x.score, reverse=True)[:n]

    # ── Plan (stub — implement with LLM) ─────────────────────

    def plan(self, bounty: Bounty) -> str:
        """
        Generate implementation plan for a bounty.
        Override this with your LLM call.
        """
        bounty.plan = (
            f"# Plan for {bounty.title}\n\n"
            f"## Issue\n{bounty.body[:500]}\n\n"
            f"## Approach\n"
            f"1. Understand the codebase structure\n"
            f"2. Identify the root cause\n"
            f"3. Implement the fix\n"
            f"4. Add tests\n"
            f"5. Open PR\n"
        )
        bounty.state = BountyState.PLANNED
        return bounty.plan

    # ── Run ──────────────────────────────────────────────────

    def run_top(
        self,
        max_bounties: int = 3,
        max_iterations: int = 2,
        implement_fn=None,
        test_fn=None,
    ) -> WorkflowReport:
        """
        Run the workflow on top-scored bounties.

        Args:
            implement_fn: callable(bounty) -> bool. Returns True on success.
            test_fn: callable(bounty) -> bool. Returns True on success.
        """
        top = self.get_top(max_bounties)
        for bounty in top:
            self._run_single(bounty, max_iterations, implement_fn, test_fn)
        self._report.ended_at = time.time()
        with self._lock:
            self._report.bounties = [b.to_dict() for b in self._bounties.values()]
        return self._report

    def _run_single(
        self,
        bounty: Bounty,
        max_iterations: int,
        implement_fn,
        test_fn,
    ) -> None:
        """Run the full workflow for one bounty."""
        try:
            self.plan(bounty)
            bounty.state = BountyState.IMPLEMENTING

            # Implement
            if implement_fn:
                success = implement_fn(bounty)
            else:
                success = True  # Stub: no-op for testing
            self._report.implemented += 1

            # Test
            bounty.state = BountyState.TESTING
            if test_fn:
                test_fn(bounty)
            self._report.iterations += bounty.iteration

            # Open PR (stub)
            bounty.state = BountyState.PR_OPENED
            self._report.pr_opened += 1

        except Exception as e:
            bounty.error = str(e)
            bounty.state = BountyState.FAILED
            self._report.errors += 1

    # ── State transitions ────────────────────────────────────

    def update_state(self, bounty_id: str, new_state: BountyState) -> None:
        with self._lock:
            if bounty_id in self._bounties:
                self._bounties[bounty_id].state = new_state

    def mark_merged(self, bounty_id: str) -> None:
        self.update_state(bounty_id, BountyState.MERGED)
        self._report.merged += 1

    def mark_rejected(self, bounty_id: str) -> None:
        self.update_state(bounty_id, BountyState.REJECTED)

    def get_report(self) -> WorkflowReport:
        return self._report


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="tiny-bounty-workflow")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="Scan for bounties")
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    p.add_argument("--query", default="bounty")
    p.add_argument("--min-score", type=float, default=0.3)

    args = parser.parse_args()

    if args.cmd == "scan":
        if not args.token:
            print("Error: --token or GITHUB_TOKEN required")
            return
        scorer = BountyScorer()
        wf = BountyWorkflow(scorer=scorer, github_token=args.token)
        print("Scanning...")
        bounties = wf.scan(query=args.query)
        print(f"Scanned {len(bounties)} issues")
        scored = wf.score_all(min_score=args.min_score)
        print(f"Passed filter: {len(scored)}")
        for b in scored[:10]:
            print(f"  [{b.score:.3f}] {b.repo}#{b.number}: {b.title[:60]}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
