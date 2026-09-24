# Security Policy

GML Code Scanner runs inside other people's CI: it checks out their repository, often on pull
requests from strangers, and holds a token that can upload code scanning results. So a
vulnerability here isn't about a hosted service. It's a bug in the scanner that someone could
trigger by putting crafted files in a repository or pull request, and it affects anyone whose
workflow runs the action on that content.

## Supported versions

Fixes ship as a new release on the current major version, and the `v1` tag is moved to it, so
workflows using `@v1` pick them up on their next run. If you pin an exact version or a commit
SHA, update the pin. Older major versions don't get backports.

## What's in scope

Roughly in order of how bad a bug would be:

- **Running code from the scanned repository.** By design the scanner never executes, evaluates
  or imports anything from the project it scans. GML is only parsed, and `.gmlscan.json` is plain
  data with no plugins or scripts. Anything that gets a crafted `.gml`, `.yy`, `.yyp` or config
  file to run commands or code is the most serious kind of report.
- **Token leaks.** The `token` input is only ever sent to the code scanning endpoint of
  `GITHUB_API_URL`. Any way to get it into logs, SARIF, annotations or a request to another host
  is in scope.
- **Reading files outside the scanned folder.** Resource paths in a `.yyp` that escape the
  project (`../`, absolute paths) and symlinks are refused. A way around that is in scope,
  especially if file contents end up in logs or SARIF.
- **Workflow-command injection.** File names and code from the scanned repo are printed with
  workflow commands paused, and annotation fields are escaped. Crafted content that still
  triggers `::` commands (fake annotations, `add-mask`, `stop-commands`...) is in scope.
- **Secrets repeated in output.** The hard-coded-secret rule masks the secrets it finds in
  reports. Output that repeats a full secret in CI logs is a bug.
- **Denial of service from a pull request.** Input that makes the parser or analysis hang, or
  exhaust memory, on a normal runner.

## What's out of scope

- **Vulnerabilities the scanner reports in your game.** That's the tool doing its job; report
  those to the game's maintainer.
- **False positives and false negatives.** Missed bugs and bad alerts are ordinary bugs; please
  open a normal issue (with a small GML snippet if you can).
- **The deliberately vulnerable sample project** in `test/fixtures/`. Its "secrets" are fake and
  its bugs are planted on purpose.
- **Anything that needs control of the workflow file itself** (a malicious `token`, `path` or
  `config` input). Whoever writes the workflow already controls the job.
- **Slow custom regexes in your own `.gmlscan.json`** (`patterns[].where`). They only slow down
  your own CI run. A pull request that edits the config can do this too, but it only wastes
  that pull request's CI minutes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting instead of a public issue: open this repo's
**Security** tab → **Report a vulnerability**. That reaches the maintainer privately, so a fix can
ship before any details are public.

If that option isn't available for some reason, open a regular issue that says you have
something to report privately, and leave out the exploit details. A way to reach you privately
will follow from there.

There's no bug bounty (this is a small, mostly solo project), but real reports are genuinely
appreciated, and you'll be credited in the release notes unless you'd rather stay anonymous.
