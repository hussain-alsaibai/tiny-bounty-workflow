"""Tests for tiny-bounty-workflow."""
import pytest
from tiny_bounty_workflow import (
    BountyScorer, AntiScamFilter, Bounty, BountyState, GitHubClient
)


class TestAntiScamFilter:
    def test_clean_bounty(self):
        f = AntiScamFilter()
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Fix bug in auth",
            body="This bug causes X. Steps to reproduce: 1. Do Y. Bounty: $100",
            labels=["bounty"],
            created_at=1740000000,
        )
        b.metadata["repo_meta"] = {"stars": 100, "created_at": 1730000000}
        clean, reason = f.check(b)
        assert clean is True

    def test_social_engineering_reject(self):
        f = AntiScamFilter()
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Bug fix",
            body="DM me for bounty on Telegram @someone",
            labels=["bounty"],
        )
        clean, reason = f.check(b)
        assert clean is False
        assert "scam_pattern" in reason

    def test_expired_bounty(self):
        f = AntiScamFilter()
        import time
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Bug",
            body="This is a bounty issue",
            labels=["bounty"],
            created_at=time.time() - 100 * 86400,  # 100 days old
        )
        clean, reason = f.check(b)
        assert clean is False
        assert reason == "expired_bounty"


class TestBountyScorer:
    def test_extract_payout_dollar(self):
        s = BountyScorer()
        assert s.extract_payout("Bounty: $500") == 500.0
        assert s.extract_payout("reward of $100.50") == 100.50
        assert s.extract_payout("payout: 250") == 250.0

    def test_extract_payout_no_amount(self):
        s = BountyScorer()
        assert s.extract_payout("Just a regular bug fix") == 0.0

    def test_clarity_score(self):
        s = BountyScorer()
        high = s._clarity_score(
            "Bug: crash on login\nSteps to reproduce:\n1. Go to /login\n2. Click submit\n```\nerror here\n```"
        )
        low = s._clarity_score("fix the bug")
        assert high > low

    def test_freshness_score(self):
        s = BountyScorer()
        import time
        new = s._freshness_score(time.time() - 86400)  # 1 day old
        old = s._freshness_score(time.time() - 120 * 86400)  # 120 days old
        assert new > old

    def test_score_clean_bounty(self):
        s = BountyScorer()
        import time
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Fix bug",
            body="Bug causes X. Steps: 1. Do Y. Bounty: $300",
            labels=["bounty"],
            competition=2,
            created_at=time.time() - 86400,  # 1 day old
        )
        b.metadata["repo_meta"] = {"stars": 100, "created_at": 1730000000}
        score, breakdown = s.score(b)
        assert score > 0
        assert "scam" not in breakdown


class TestBountyState:
    def test_bounty_active_states(self):
        active = BountyState.SCORED
        terminal = BountyState.MERGED
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Fix",
            body="",
            state=active,
        )
        assert b.is_active is True
        b.state = terminal
        assert b.is_active is False

    def test_bounty_to_dict(self):
        b = Bounty(
            id="test/1",
            repo="test/repo",
            number=1,
            title="Fix",
            body="",
        )
        d = b.to_dict()
        assert d["state"] == "scanned"
        assert d["id"] == "test/1"
