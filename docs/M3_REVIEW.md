# M3 PR #7 review

Last updated: 4 October 2026.

## Scope

PR #7: `M3: Schema Agent with versioned ECS parsers, validation, and quarantine`

Head reviewed:

`44df901c85753d88b9072ef6c2ae48c2e8041b4c`

This review is read-only. The M3 member's PR and branch must not be modified or merged unless the project lead explicitly requests it.

## Current verdict

The latest M3 implementation is substantially better than the earlier revision. A rewrite is not required.

The implementation now covers the intended M3 responsibilities:

- schema registry
- format classification
- ECS mapping
- candidate parser validation
- immutable schema versions
- failed-record quarantine
- raw input preservation
- stable document IDs
- unknown-format fallback
- bounded parser-generation behavior

## Independent evidence

The member reported 101 passing offline tests. This was independently rerun on the VPS against the exact PR head.

VPS verification run: `37205262630`

Result:

```text
Ran 101 tests in 3.423s

OK
```

Mutation verification was also rerun independently.

VPS mutation run: `37205334790`

Result:

```json
{"pipeline_mutations":4830,"agent_mutations":4830,"unexpected_failures":0,"examples":[]}
```

A temporary integration merge simulation combined current `main`, M3 PR #7, and the M1 replacement without changing the repository's `main` branch.

VPS merge-simulation run: `37205417843`

Result:

- 101 M3 tests passed
- 4,830 pipeline mutations passed without unexpected failure
- 4,830 agent mutations passed without unexpected failure
- M1 Compose configuration remained valid

The M3 Elasticsearch mapping was compared with the M1 replacement normalized production template. Their `template.mappings` content is identical.

Five records from M3's `known-mixed.ndjson` fixture were also normalized successfully:

```json
{"accepted":5,"processed":5,"quarantined":0}
```

Their M3 bulk export was accepted by the secured M1 Elasticsearch mapping with no bulk mapping errors.

## Improvements confirmed

The latest revision correctly addresses the earlier review findings:

- Zeek HTTP Host maps to `url.domain` rather than computer `host.name`.
- Flat Sysmon input is detected without requiring a source hint.
- Empty or whitespace-only usernames and executable paths are rejected.
- Malformed records are isolated rather than aborting later records.
- Windows event codes are canonicalized before source-specific checks.
- integer and port ranges are bounded to Elasticsearch-compatible values.
- conflicting dotted and nested field representations are quarantined.
- malformed known-source records stay on the known parser path instead of being treated as unknown custom formats.
- invalid UTF-8, non-finite JSON, excessive nesting, and unsafe registry input are handled defensively.
- parser versions remain immutable once registered.

## Remaining work for the M3 author

At the latest review, PR #7 was still 12 commits behind `main` and had no GitHub Actions run on its head.

Before the PR should be considered final, the M3 author should:

1. sync the branch with the latest `main`;
2. add CI that runs `python -m unittest discover -s tests -v`;
3. add CI that runs `python tests/mutation_check.py`;
4. rerun and show the green CI evidence after the sync;
5. when M2 becomes available, verify the parser against real M2 connector output.

The PR itself already states that real connector inputs have not yet been tested. That is a current integration limitation, not a reason to rewrite M3.

## Merge decision

**Do not merge yet.**

Reason: the code quality is good, but the branch should first be synced, automatically tested by CI, and later connected to real M2 output when available.

The project lead has explicitly requested review-only handling of M3 unless further help is requested.
