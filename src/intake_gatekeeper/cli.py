from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from intake_gatekeeper import __version__, output
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
    scan.add_argument(
        "--osv",
        action="store_true",
        help="look up known vulnerabilities on OSV.dev (sends ecosystem, name and version of "
        "each queryable component; nothing else)",
    )
    scan.add_argument(
        "--osv-url", default=DEFAULT_URL, help="OSV API origin (default: %(default)s)"
    )
    scan.add_argument("--policy", type=Path, help="policy TOML file")
    scan.add_argument("--json", type=Path, metavar="FILE", help="write the full JSON report")
    scan.add_argument("--sarif", type=Path, metavar="FILE", help="write SARIF 2.1.0")
    scan.add_argument("--cyclonedx", type=Path, metavar="FILE", help="write a CycloneDX 1.6 SBOM")
    scan.add_argument("--markdown", type=Path, metavar="FILE", help="write a Markdown summary")
    scan.add_argument(
        "--fail-on",
        choices=sorted(_FAIL_LEVELS),
        default="reject",
        help="decision that produces exit status 1 (default: %(default)s)",
    )
    scan.add_argument("--max-files", type=int, default=Limits.max_files, help=argparse.SUPPRESS)
    scan.add_argument("-q", "--quiet", action="store_true", help="do not print the summary")

    commands.add_parser("rules", help="list configuration rules")
    return parser


def _list_rules() -> int:
    for rule in RULES.values():
        print(f"{rule.id:36} {rule.severity.label:8} {rule.title}")
    return EXIT_OK


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
        osv = osv_factory(validate_base_url(args.osv_url)) if args.osv else None
        try:
            report = run_scan(args.target, policy, osv, Limits(max_files=args.max_files))
        finally:
            if osv is not None:
                osv.close()
        writers = (
            (args.json, output.to_json),
            (args.sarif, output.to_sarif),
            (args.cyclonedx, output.to_cyclonedx),
            (args.markdown, output.to_markdown),
        )
        for path, render in writers:
            if path is not None:
                output.write_atomic(path, render(report))
    except GatekeeperError as error:
        print(f"intake-gatekeeper: error: {clean_text(str(error), 500)}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as error:
        print(f"intake-gatekeeper: error: {clean_text(str(error), 500)}", file=sys.stderr)
        return EXIT_USAGE
    if not args.quiet:
        sys.stdout.write(output.to_text(report))
    return EXIT_GATE if report.decision in _FAIL_LEVELS[args.fail_on] else EXIT_OK
