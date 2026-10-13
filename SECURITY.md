# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Sushant-Nemade/software-intake-gatekeeper/security/advisories/new).
Do not open a public issue for a suspected vulnerability. Include the version, the command you ran
and, if possible, a minimal input that reproduces the problem. Do not attach proprietary binaries.

## Threat model in brief

The scanner treats every input file as hostile:

- It only reads files. It never executes, loads, unpacks to disk or follows symbolic links and
  Windows junctions found inside the target.
- ASAR archives are parsed in memory with bounded header sizes, validated entry names and offset
  checks. Unsafe entries are reported as coverage gaps.
- File counts, nesting depth, manifest, script and binary sizes are bounded. Hitting a limit is a
  blocking coverage gap, so a truncated scan cannot be approved.
- Text from the target (package names, paths, snippets) is stripped of control and bidirectional
  characters before it reaches the terminal, and escaped or confined to code spans in Markdown.
- Network access happens only with `--osv`. Requests go to an HTTPS origin (HTTP is accepted only
  for localhost), redirects are not followed, TLS uses the operating system trust store and only
  the ecosystem, name and version of each component are sent.

## Supported versions

Only the latest release on `main` receives fixes.
