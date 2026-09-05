# tiny-bounty-workflow — Autonomous Bounty Workflow Engine

> **State machine for autonomous bounty hunting.**
> Scan → Score → Plan → Implement → Test → PR → Review → Iterate
> Zero dependencies. MIT. ~500 lines.

```bash
pip install tiny-bounty-workflow
# or just copy tiny_bounty_workflow/bounty_workflow.py
```

## Why This Exists

Most bounty hunters are scripts. This is a **workflow engine**:

- State machine with explicit transitions
- Anti-scam filters (rejects ~60% of labeled bounties)
- Scoring model with 5 weighted factors
- Iteration loop for review feedback
- Memory integration with `tiny-agent-memory`

## The Workflow

```
SCAN → SCORE → PLAN → IMPLEMENT → TEST → PR → REVIEW
                                              ↓
                                         ITERATE ←──────┐
                                              ↓           │
                                         (comments)      │
                                              ↓           │
                                         IMPLEMENT ─────┘
```

The iteration loop is the differentiator. Most agents give up after the first PR. Production agents iterate on review feedback.

## Quick Start

```python
import os
from tiny_bounty_workflow import BountyWorkflow, BountyScorer

# Configure scoring weights for your agent profile
scorer = BountyScorer(
    w_payout=0.30,
    w_competition=0.20,
    w_stack=0.25,
    w_clarity=0.15,
    w_freshness=0.10,
)

wf = BountyWorkflow(
    scorer=scorer,
    github_token=os.environ["GITHUB_TOKEN"],
    agent_languages=["python", "javascript"],
)

# Scan for bounties
bounties = wf.scan(query="bounty", min_bounty=50)
print(f"Found {len(bounties)} issues")

# Score and filter
scored = wf.score_all(min_score=0.3)
print(f"Passed filter: {len(scored)}")

# Run the workflow
report = wf.run_top(max_bounties=2, max_iterations=3)
print(f"Merged: {report.merged}, PRs opened: {report.pr_opened}")
```

## Scoring Model

```
Score = w₁·payout + w₂·(1/competition) + w₃·stack_fit + w₄·clarity + w₅·freshness
```

| Factor | Weight | Normalization |
|--------|--------|--------------|
| Payout | 0.30 | min(payout/500, 1.0) |
| Competition | 0.20 | 1/(1 + prs/10) |
| Stack fit | 0.25 | 0-1, configured per agent |
| Clarity | 0.15 | Heuristic from issue body |
| Freshness | 0.10 | 1.0 for <7 days, 0.2 for >90 days |

## Anti-Scam Filters

The workflow rejects bounties that are:
- **High competition**: >50 existing PRs
- **Expired**: >90 days old with no payout listed
- **New empty repos**: <5 stars, <30 days old
- **Social engineering**: "dm me", "contact on WhatsApp", "paypal me"
- **Non-existent payouts**: Label says bounty, body says nothing

## CLI

```bash
# Scan for bounties
GITHUB_TOKEN=ghp_... python -m tiny_bounty_workflow scan --query "bounty" --min-score 0.3

# With your own LLM for planning
python -m tiny_bounty_workflow scan --token $GITHUB_TOKEN
```

## Integration with OpenClaw

```python
from tiny_bounty_workflow import BountyWorkflow
from tiny_agent_memory import TieredMemory

memory = TieredMemory(agent_id="bounty-agent-1")
wf = BountyWorkflow(scorer=scorer, github_token=token, memory=memory)

# Agent's memory survives restarts
bounties = wf.scan(languages=["python"])
for b in wf.get_top(3):
    memory.remember(f"Considering bounty: {b.title}", tags=["bounty", b.repo])
```

## Dependencies

**Zero.** Uses stdlib `urllib` for GitHub API calls.

## License

MIT © 2026 Hussain Al-Saibai
