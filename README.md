# AI Cybersecurity After Mythos: The Jagged Frontier

Supporting materials for the blog post: [AI Cybersecurity After Mythos: The Jagged Frontier](https://aisle.com/blog/ai-cybersecurity-after-mythos-the-jagged-frontier)

**Author:** Stanislav Fort, Founder and Chief Scientist at [AISLE](https://aisle.com)

## What this is

On April 7, 2026, Anthropic announced Claude Mythos Preview and Project Glasswing. Their technical blog post showcased several specific vulnerabilities as evidence of Mythos's cybersecurity capabilities.

We took those public showcase vulnerabilities, isolated the relevant code, and tested whether small, cheap, and open-weights models could recover the same analysis. This repository contains the exact prompts used and the full model responses, so anyone can verify our results or reproduce the experiments.

## Summary of findings

| Test | What we tested | Result |
|---|---|---|
| FreeBSD NFS (CVE-2026-4747) | Mythos's flagship "fully autonomous" exploit | 8/8 models detected it, including a 3.6B-active model at $0.11/M tokens |
| FreeBSD exploitation reasoning | Can models assess exploitability? | 7/7 correct on mitigations, ROP strategy, gadget sequences |
| FreeBSD payload constraint | Can models solve a real exploit engineering problem? | No model found Mythos's multi-round approach, but several proposed valid alternatives |
| OpenBSD SACK (27-year-old bug) | Mythos's subtlest showcase find | GPT-OSS-120b (5.1B active) recovered the full public chain in one call |
| OWASP false-positive | Can models distinguish real vulns from false alarms? | Near-inverse scaling: 3.6B open model outperforms Sonnet 4.5 and GPT-5.4 Pro |

## Repository structure

```
prompts/
  freebsd-detection.md        # Prompt for FreeBSD NFS vulnerability detection
  freebsd-exploitation.md     # Follow-up prompt on exploitability
  freebsd-payload.md          # Follow-up prompt on payload size constraint
  openbsd-sack.md             # Prompt for OpenBSD SACK vulnerability
  owasp-false-positive.md     # Prompt for OWASP false-positive discrimination

transcripts/
  freebsd-detection.md        # Full responses from 8 models
  freebsd-exploitation.md     # Full exploitation reasoning responses
  freebsd-payload.md          # Full payload constraint responses
  openbsd-sack.md             # Full responses from 8 models
  owasp-false-positive.md     # Full responses from 25+ models across all labs
```

## Reproducing the experiments

All experiments were run via [OpenRouter](https://openrouter.ai/) using the chat playground. To reproduce:

1. Go to OpenRouter and select the model you want to test
2. Paste the prompt from the relevant file in `prompts/`
3. Compare the response to our transcripts

The prompts provide the vulnerable function with architectural context (what the function does, where inputs come from). This simulates what a well-designed discovery scaffold provides after identifying a function as security-relevant. See the caveats section of the blog post for a full discussion of what these experiments do and do not show.

## Models tested

**Open-weights / open-source:** Kimi K2, DeepSeek R1 0528, Qwen3 32B, Gemma 4 31B, GPT-OSS-20b (3.6B active), GPT-OSS-120b (5.1B active), Codestral 2508

**Closed-source:** OpenAI o3, GPT-4.1 (+ Mini, Nano), GPT-5.4 (Mini, Nano, Pro), Google Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 3.1 Flash Lite

**Anthropic (13 models):** Claude 3 Haiku, Claude 3.5 Haiku, Claude Opus 3, Claude 3.5 Sonnet, Claude 3.7 Sonnet, Claude Haiku 4.5, Claude Sonnet 4, Claude Sonnet 4.5, Claude Sonnet 4.6, Claude Opus 4, Claude Opus 4.1, Claude Opus 4.5, Claude Opus 4.6

## Related work

- [AI found 12 of 12 OpenSSL zero-days](https://www.lesswrong.com/posts/...) (LessWrong, January 2026)
- [What AI Security Research Looks Like When It Works](https://aisle.com/blog/what-ai-security-research-looks-like-when-it-works) (AISLE blog, February 2026)
- [Anthropic: Assessing Claude Mythos Preview's cybersecurity capabilities](https://red.anthropic.com/2026/mythos-preview/) (April 2026)
- [Anthropic: Project Glasswing](https://www.anthropic.com/research/project-glasswing) (April 2026)
