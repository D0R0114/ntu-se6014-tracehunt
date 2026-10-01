# TraceHunt (SE6014 group project)

This is our group project for SE6014 Security Monitoring. We are building TraceHunt, a threat hunting assistant that runs on the Elastic Stack. It takes in three kinds of logs: Windows Security events from an EVTX drop folder, Sysmon events through Winlogbeat, and Zeek network logs. A schema agent picks or creates the right ECS parsers and validates them, and a custom MCP server exposes typed read-only search tools so an LLM agent can query the data. Every tool call gets recorded in an evidence ledger with the exact query, a hash, and the document IDs it returned.

The hunt follows a fixed workflow. The agent starts from a hypothesis, builds a coverage checklist, runs queries, verifies what it finds, and ends with a verdict of confirmed, rejected, or inconclusive. In the final weeks we freeze the setup and run the same hunt twice to measure repeatability.

## Who does what

M1 owns the ELK stack and the integration work: Docker Compose, index templates, access control.

M2 builds the connectors for the three log sources.

M3 handles schema and data quality: the parser registry, ECS mapping, the classifier, and quarantine.

M4 builds the MCP server and the search tools, including input validation and the evidence ledger.

M5 implements the hunt workflow state machine and the verifier.

M6 runs the experiment and owns the product side: ground truth, decoy traffic, the two-run comparison, and the final pitch.

## How we work

Main is locked down with branch protection. Nobody pushes to it directly. Every change reaches main through a pull request that the project lead reviews and merges, and the lead is the only person with write access to the repository.

Members work through forks. Fork this repository, do your work on a branch in your fork, and open a pull request against main here. The lead reviews it, tests it, and merges it once it is sound. Review comments come back on the pull request. You can also open issues and comment even without write access.

Name your branch with your role and the topic, for example m1/elk-setup or m4/mcp-tools.

One task is one issue. Add your M label and attach it to the right milestone. Write the acceptance criteria in the issue body, and put "closes #12" in the PR description so the issue closes automatically when the PR merges.

If you get stuck, add the blocked label and leave a comment saying why. It is an early warning for the team, not a failure.

## Schedule

Week 1, by 9 Oct: design freeze, architecture and role boundaries agreed.

Week 2, by 16 Oct: all three sources landing in ELK.

Week 3, by 23 Oct: validated parsers, MCP tools, and the evidence ledger working.

Week 4, by 30 Oct: the full hunt workflow runs end to end.

Week 5, by 6 Nov: frozen two-run repeatability experiment.

Week 6, by 13 Nov: final report and demo.

## Folders

Each member works in their own folder: m1-elk, m2-connectors, m3-schema, m4-mcp, m5-hunt, m6-experiment. Shared material goes in docs for design notes and decisions, evidence for hunt run artifacts, and lab for the scenario files (benign logon, encoded PowerShell, the HTTP beacon, and decoy traffic).

The ground truth manifest stays with M6 and is not committed to this repo. Hunt verdicts are scored against it only after the frozen runs are done.
