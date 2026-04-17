# Security Audit Report

The following vulnerabilities were identified and have now been patched.

## 1. Critical Vulnerability: Docker Sandbox Fallback executes malicious commands on the host directly

**Status:** Patched

**Severity:** Critical

**Location:** `contop-server/tools/docker_sandbox.py` in `_fallback_run()` and `contop-server/core/dual_tool_evaluator.py`.

**Description:**
The application uses a `DualToolEvaluator` to classify shell commands as either `host` (safe) or `sandbox` (dangerous/destructive/forbidden/restricted). If a command is classified as `sandbox` (for example, commands that match the forbidden commands list like `rm -rf /` or access restricted paths), the evaluator routes the command to be executed inside a Docker container using `DockerSandbox`.
However, if Docker is not installed or fails to start, `DockerSandbox.run` delegates to `_fallback_run()`. The `_fallback_run()` method executed the command directly on the host machine using `HostSubprocess().run()` with a restricted timeout but **NO sandbox isolation**.

**Impact:**
This completely defeats the purpose of the sandbox. An attacker or a malicious LLM agent could issue destructive commands, and if the user's machine simply does not have Docker running or installed, the commands would be executed natively on the host machine, potentially leading to total system compromise, data loss, or unrestricted access.

**Resolution:**
The `_fallback_run()` method has been updated to explicitly refuse to run the command on the host. It now fails securely, returning an error response to the caller and notifying the user.

## 2. Medium/High Vulnerability: Path Traversal and Bypass in Restricted Path Checks

**Status:** Patched

**Severity:** Medium/High

**Location:** `contop-server/core/dual_tool_evaluator.py` in `_path_referenced()`.

**Description:**
The application prevents access to sensitive files and directories (like `/etc/passwd` or `C:\Windows`) by checking if the restricted path strings are present in the requested file paths or commands. The implementation of `_path_referenced(command, path)` relied on simple substring matching (e.g. `path in command` or `path.lower() in command.lower()`).
This naive string matching did not resolve paths and was highly susceptible to path traversal and normalization bypasses.

**Impact:**
An attacker or malicious LLM could easily bypass the restricted paths check. For example, if `/etc/passwd` is restricted, an attacker could access it by requesting `/etc//passwd`, `/etc/./passwd`, or `/tmp/../etc/passwd`. Because the exact string `/etc/passwd` was not present, the `DualToolEvaluator` classified the command as `host` (safe), granting the agent unauthorized read/write access to sensitive files.

**Resolution:**
The `_path_referenced` method has been updated to resolve user inputs and paths into their absolute paths using `os.path.abspath(os.path.expanduser(token))`. The parsed and resolved path is then checked against the resolved restricted path, eliminating path traversal bypasses.


## Recommendation

**Is this application safe to use as a secure remote desktop application?**

**Yes, with caveats.**

Both critical and high-severity security issues identified during the initial audit have been resolved:
1. The **Docker Sandbox fallback** no longer delegates `sandbox` designated commands to the host OS.
2. The **Restricted Path Isolation** checks accurately resolve paths using OS primitives, blocking path traversal and manipulation tactics.

However, users should always exercise caution and limit the privileges given to any remote desktop application. Ensure that only trusted users are paired via the mobile application, and consider maintaining regular backups in the event of unexpected behavior.
