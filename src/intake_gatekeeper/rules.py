from __future__ import annotations

from dataclasses import dataclass

from intake_gatekeeper.model import Severity

ELECTRON_SECURITY = "https://www.electronjs.org/docs/latest/tutorial/security"
ELECTRON_FUSES = "https://www.electronjs.org/docs/latest/tutorial/fuses"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    help: str
    help_uri: str


RULES: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule(
            "EGK-JS-NODE-INTEGRATION",
            "Renderer has Node.js integration enabled",
            Severity.HIGH,
            "nodeIntegration: true gives web content direct Node.js access; any XSS becomes "
            "code execution. Keep it disabled and expose narrow APIs through a preload script.",
            ELECTRON_SECURITY + "#2-do-not-enable-nodejs-integration-for-remote-content",
        ),
        Rule(
            "EGK-JS-CONTEXT-ISOLATION-OFF",
            "Context isolation is disabled",
            Severity.HIGH,
            "contextIsolation: false lets page scripts tamper with preload globals and privileged "
            "APIs. Leave context isolation enabled (the default since Electron 12).",
            ELECTRON_SECURITY + "#3-enable-context-isolation",
        ),
        Rule(
            "EGK-JS-WEB-SECURITY-OFF",
            "Web security (same-origin policy) is disabled",
            Severity.HIGH,
            "webSecurity: false disables the same-origin policy and allows mixed content.",
            ELECTRON_SECURITY + "#6-do-not-disable-websecurity",
        ),
        Rule(
            "EGK-JS-INSECURE-CONTENT",
            "Insecure (HTTP) content may run on HTTPS pages",
            Severity.HIGH,
            "allowRunningInsecureContent: true lets scripts from plain HTTP origins run in secure pages.",
            ELECTRON_SECURITY + "#8-do-not-enable-allowrunninginsecurecontent",
        ),
        Rule(
            "EGK-JS-SANDBOX-OFF",
            "Renderer sandbox is disabled",
            Severity.MEDIUM,
            "sandbox: false in webPreferences removes the Chromium OS-level sandbox for the "
            "renderer process.",
            ELECTRON_SECURITY + "#4-enable-process-sandboxing",
        ),
        Rule(
            "EGK-JS-NODE-INTEGRATION-EXTENDED",
            "Node.js integration is enabled in sub-frames or workers",
            Severity.MEDIUM,
            "nodeIntegrationInSubFrames or nodeIntegrationInWorker extends Node.js access beyond "
            "the main frame.",
            ELECTRON_SECURITY,
        ),
        Rule(
            "EGK-JS-REMOTE-MODULE",
            "Deprecated remote module is enabled",
            Severity.MEDIUM,
            "enableRemoteModule: true exposes main-process objects to renderers. The module was "
            "removed from Electron core in version 14.",
            ELECTRON_SECURITY,
        ),
        Rule(
            "EGK-JS-WEBVIEW-TAG",
            "The <webview> tag is enabled",
            Severity.LOW,
            "webviewTag: true allows embedding guest content; verify will-attach-webview "
            "handlers restrict its preferences.",
            ELECTRON_SECURITY + "#12-verify-webview-options-before-creation",
        ),
        Rule(
            "EGK-JS-EXPERIMENTAL-FEATURES",
            "Experimental Chromium features are enabled",
            Severity.LOW,
            "experimentalFeatures: true enables untested web platform features.",
            ELECTRON_SECURITY + "#9-do-not-enable-experimental-features",
        ),
        Rule(
            "EGK-JS-OPEN-EXTERNAL",
            "shell.openExternal call found",
            Severity.INFO,
            "Passing untrusted URLs to shell.openExternal can launch arbitrary protocol "
            "handlers. Confirm that every call validates the URL scheme and host.",
            ELECTRON_SECURITY + "#15-do-not-use-shellopenexternal-with-untrusted-content",
        ),
        Rule(
            "EGK-FUSE-RUN-AS-NODE",
            "RunAsNode fuse is enabled",
            Severity.MEDIUM,
            "ELECTRON_RUN_AS_NODE turns this signed executable into a general-purpose Node.js "
            "runtime that attackers can abuse to run code under a trusted binary.",
            ELECTRON_FUSES + "#runasnode",
        ),
        Rule(
            "EGK-FUSE-NODE-OPTIONS",
            "NODE_OPTIONS environment variable is honoured",
            Severity.MEDIUM,
            "The EnableNodeOptionsEnvironmentVariable fuse lets environment variables inject "
            "code into the main process.",
            ELECTRON_FUSES + "#nodeoptions",
        ),
        Rule(
            "EGK-FUSE-NODE-INSPECT",
            "Node.js inspector command-line flags are honoured",
            Severity.MEDIUM,
            "The EnableNodeCliInspectArguments fuse allows --inspect flags that attach a "
            "debugger to the main process.",
            ELECTRON_FUSES + "#nodecliinspect",
        ),
        Rule(
            "EGK-FUSE-ASAR-INTEGRITY-OFF",
            "Embedded ASAR integrity validation is disabled",
            Severity.LOW,
            "Without the EnableEmbeddedAsarIntegrityValidation fuse, a modified app.asar is "
            "loaded without integrity checks.",
            ELECTRON_FUSES + "#embeddedasarintegrityvalidation",
        ),
        Rule(
            "EGK-FUSE-LOAD-OUTSIDE-ASAR",
            "Application code may load from outside app.asar",
            Severity.LOW,
            "Without the OnlyLoadAppFromAsar fuse, Electron also searches unpacked app folders, "
            "which weakens integrity checks.",
            ELECTRON_FUSES + "#onlyloadappfromasar",
        ),
        Rule(
            "EGK-FUSE-COOKIE-ENCRYPTION-OFF",
            "Cookie encryption is disabled",
            Severity.LOW,
            "Without the EnableCookieEncryption fuse, the cookie store is not encrypted with OS-level keys.",
            ELECTRON_FUSES + "#cookieencryption",
        ),
        Rule(
            "EGK-FUSE-FILE-PROTOCOL-PRIVILEGES",
            "file:// pages receive extra privileges",
            Severity.LOW,
            "The GrantFileProtocolExtraPrivileges fuse gives file:// pages behaviour beyond a "
            "normal web origin.",
            ELECTRON_FUSES + "#grantfileprotocolextraprivileges",
        ),
    )
}
