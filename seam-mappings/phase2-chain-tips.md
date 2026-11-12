# Phase 2 — flex-mcp chain tips for Phase 3 continuation

All Phase 2 jobs ran with `store: true` on `gpt-6-astra` / `xhigh` / `flex`.
Local flex-mcp ledger rows were deleted after materialization, but the
provider-side stored responses remain chainable: `previous_response_id`
does **not** require a local ledger row (per flex-mcp client guide).

Chain the Phase 3 worker for each track off its **tip** response_id below.
Tips carry the full server-side conversation (sources + full spec + appendix),
so children should get near-total prompt-cache hits on the ~117–181K cached
input tokens instead of reburning them.

## Chain tips (use as `previous_response_id`)

| Track | Spec on disk | Tip response_id | Tip role |
|---|---|---|---|
| 2.1 | `seam-mappings/crawler-seam-mapping.md` | `resp_01ac2f0a85115fe4006af4e3d942fc87d28608ad2610aa7c91` | repair (Appendix A) |
| 2.2 | `seam-mappings/circus-tent-seam-mapping.md` | `resp_0b422a40d7526654006af4e3da013487d2af9192d70fcb4eb6` | repair (Appendix A) |
| 2.3 | `seam-mappings/ringmaster-seam-mapping.md` | `resp_020c07a99943204c006af4e3dab12487d2bcbd0e11dd0e965d` | repair (Appendix A) |
| 2.4 | `seam-mappings/hellscape-seam-mapping.md` | `resp_085e54dd8d1c7564006af4e162574087d28f8b42ed559eccc9` | full-doc child (no repair needed) |
| 2.5 | `seam-mappings/job-hunter-seam-mapping.md` | `resp_056c03bbb9a59b71006af4e163030487d2a4bd2c163b1d1c6c` | full-doc child (no repair needed) |

## Full chain map (all 13 submissions, all ledger-deleted)

| Track | Parent (`incomplete`, 24K cap) | Doc child (`completed`, 48K cap) | Repair child (`completed`, 8K cap) |
|---|---|---|---|
| 2.1 | `resp_01ac2f0a85115fe4006af4df2f4ea487d2869222e06cf63996` | `resp_01ac2f0a85115fe4006af4e1605c3887d28484da26b677ba5b` | `resp_01ac2f0a85115fe4006af4e3d942fc87d28608ad2610aa7c91` |
| 2.2 | `resp_0b422a40d7526654006af4df3b1cac87d28ca8344b86a7e08a` | `resp_0b422a40d7526654006af4e161211487d2a06b2f35b19a4e7f` | `resp_0b422a40d7526654006af4e3da013487d2af9192d70fcb4eb6` |
| 2.3 | `resp_020c07a99943204c006af4df3bc41c87d290eb65209d247cb2` | `resp_020c07a99943204c006af4e161c62887d2b9c79093e3934b6d` | `resp_020c07a99943204c006af4e3dab12487d2bcbd0e11dd0e965d` |
| 2.4 | `resp_085e54dd8d1c7564006af4df3c6cf487d29dceb50d78b0191f` | `resp_085e54dd8d1c7564006af4e162574087d28f8b42ed559eccc9` | — |
| 2.5 | `resp_056c03bbb9a59b71006af4df3d2ca087d2be325c5a00134c76` | `resp_056c03bbb9a59b71006af4e163030487d2a4bd2c163b1d1c6c` | — |

## Token spend reference (input / cached-input / output / reasoning / total)

Parents: 2.1: 157065/0/24000/3623/181065 · 2.2: 125383/0/24000/2070/149383 ·
2.3: 117390/0/24000/1948/141390 · 2.4: 137111/0/24000/3341/161111 ·
2.5: 128873/0/24000/3106/152873.

Doc children: 2.1: 181188/157062/21434/1034/202622 ·
2.2: 149506/125380/20703/1034/170209 ·
2.3: 141513/117387/20858/1552/162371 ·
2.4: 161234/137108/21790/1796/183024 ·
2.5: 152996/128870/21345/1552/174341.

Repairs: 2.1: 202787/181185/634/0/203421 ·
2.2: 170339/149503/927/276/171266 · 2.3: 162520/141510/526/192/163046.

## Chaining template for Phase 3

```json
flex_submit({
  "model": "gpt-6-astra",
  "reasoning_effort": "xhigh",
  "service_tier": "flex",
  "max_output_tokens": 48000,
  "store": true,
  "metadata": { "track": "<3.x>", "phase": "3" },
  "previous_response_id": "<TIP_FROM_TABLE_ABOVE>",
  "input": "<PHASE_3_WORKER_PROMPT>"
})
```

Caveats:
- Server-side stored responses have a finite retention window (weeks-scale);
  chain sooner rather than later. If a tip has expired, the fallback is a
  fresh submission with the on-disk spec + contracts re-attached (full input
  cost, no lost work — every document is complete on disk).
- `flex_status` / `flex_get` on the deleted rows will return `not_found`
  (local ledger is clean by design); only `flex_submit` chaining still works.
- The on-disk `Appendix A` sections in the 2.1/2.2/2.3 specs were already
  merged from the repair responses, so chaining off the tips and chaining off
  the doc children differ only in conversational preamble, not content.
