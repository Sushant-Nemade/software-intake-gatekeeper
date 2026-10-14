from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from intake_gatekeeper import __version__, output
from intake_gatekeeper.diff import compare
from intake_gatekeeper.engine import run_scan
from intake_gatekeeper.model import Decision, GatekeeperError, clean_text
from intake_gatekeeper.osv import DEFAULT_URL, OsvClient, validate_base_url
from intake_gatekeeper.policy import load_policy
from intake_gatekeeper.rules import RULES
from intake_gatekeeper.scanner import Limits

EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
_FAIL_LEVELS = {
    "reject": {Decision.REJECT},
    "review": {Decision.REJECT, Decision.REVIEW},
    "never": set(),
}


def _common(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--osv",
        action="store_true",
        help="look up known vulnerabilities on OSV.dev (sends ecosystem, name and version of "
        "each queryable component; nothing else)",
    )
    command.add_argument("--osv-url", default=DEFAULT_URL, help="OSV API origin (default: %(default)s)")
    command.add_argument("--policy", type=Path, help="policy TOML file")
    command.add_argument("--json", type=Path, metavar="FILE", help="write the full JSON report")
    command.add_argument(
        "--sarif",
        type=Path,
        metavar="FILE",
        help="write SARIF 2.1.0 (paths are relative to the current directory when the target "
        "is inside it, which is what GitHub code scanning expects)",
    )
    command.add_argument("--cyclonedx", type=Path, metavar="FILE", help="write a CycloneDX 1.6 SBOM")
    command.add_argument("--markdown", type=Path, metavar="FILE", help="write a Markdown summary")
    command.add_argument(
        "--fail-on",
        choices=sorted(_FAIL_LEVELS),
        default="reject",
        help="decision that produces exit status 1 (default: %(default)s)",
    )
    command.add_argument("--max-files", type=int, default=Limits.max_files, help=argparse.SUPPRESS)
    command.add_argument("-q", "--quiet", action="store_true", help="do not print the summary")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intake-gatekeeper",
        description="Evidence-first intake checks for third-party apps and binaries. "
        "Reads files only; never executes or extracts the target.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a directory, archive or binary")
    scan.add_argument("target", type=Path, help="installed app directory, .asar or executable")
    _common(scan)

    diff = commands.add_parser(
        "diff",
        help="compare two versions and gate the update on what it adds",
        description="Scan the previous and the new version and report new and resolved findings, "
        "component changes, Electron fuse changes, new network endpoints and new binaries.",
    )
    diff.add_argument("old", type=Path, help="previous version (directory, .asar or executable)")
    diff.add_argument("new", type=Path, help="new version")
    _common(diff)

    commands.add_parser("rules", help="list configuration rules")
    return parser


def _list_rules() -> int:
    for rule in RULES.values():
        print(f"{rule.id:36} {rule.severity.label:8} {rule.title}")
    return EXIT_OK


def _write(outputs: Sequence[tuple[Path | None, Callable[[], str]]]) -> None:
    for path, render in outputs:
        if path is not None:
            output.write_atomic(path, render())


def main(
    argv: Sequence[str] | None = None,
    osv_factory: Callable[[str], OsvClient] = OsvClient,
) -> int:
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    if args.command == "rules":
        return _list_rules()
    try:
        if args.max_files < 1:
            raise GatekeeperError("--max-files must be positive")
        policy = load_policy(args.policy)
        limits = Limits(max_files=args.max_files)
        osv = osv_factory(validate_base_url(args.osv_url)) if args.osv else None
        try:
            if args.command == "diff":
                old_report = run_scan(args.old, policy, osv, limits)
                new_report = run_scan(args.new, policy, osv, limits)
            else:
                report = run_scan(args.target, policy, osv, limits)
        finally:
            if osv is not None:
                osv.close()
        if args.command == "diff":
            diff = compare(old_report, new_report, policy)
            prefix = output.sarif_prefix(args.new, Path.cwd())
            _write(
                [
                    (args.json, lambda: output.to_diff_json(diff)),
                    (args.sarif, lambda: output.diff_sarif(diff, prefix)),
                    (args.cyclonedx, lambda: output.to_cyclonedx(new_report)),
                    (args.markdown, lambda: output.to_diff_markdown(diff)),
                ]
            )
            summary, decision = output.to_diff_text(diff), diff.decision
        else:
            prefix = output.sarif_prefix(args.target, Path.cwd())
            _write(
                [
                    (args.json, lambda: output.to_json(report)),
                    (args.sarif, lambda: output.to_sarif(report, prefix)),
                    (args.cyclonedx, lambda: output.to_cyclonedx(report)),
                    (args.markdown, lambda: output.to_markdown(report)),
                ]
            )
            summary, decision = output.to_text(report), report.decision
    except (GatekeeperError, OSError) as error:
        print(f"intake-gatekeeper: error: {clean_text(str(error), 500)}", file=sys.stderr)
        return EXIT_USAGE
    if not args.quiet:
        sys.stdout.write(summary)
    return EXIT_GATE if decision in _FAIL_LEVELS[args.fail_on] else EXIT_OK
