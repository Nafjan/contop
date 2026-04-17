# Security Audit Report

## 1. Critical Vulnerability: Docker Sandbox Fallback executes malicious commands on the host directly

**Severity:** Critical

**Location:** `contop-server/tools/docker_sandbox.py` in `_fallback_run()` and `contop-server/core/dual_tool_evaluator.py`.

**Description:**
The application uses a `DualToolEvaluator` to classify shell commands as either `host` (safe) or `sandbox` (dangerous/destructive/forbidden/restricted). If a command is classified as `sandbox` (for example, commands that match the forbidden commands list like `rm -rf /` or access restricted paths), the evaluator routes the command to be executed inside a Docker container using `DockerSandbox`.
However, if Docker is not installed or fails to start, `DockerSandbox.run` delegates to `_fallback_run()`. The `_fallback_run()` method executes the command directly on the host machine using `HostSubprocess().run()` with a restricted timeout but **NO sandbox isolation**.

**Impact:**
This completely defeats the purpose of the sandbox. An attacker or a malicious LLM agent can issue destructive commands, and if the user's machine simply does not have Docker running or installed, the commands will be executed natively on the host machine, potentially leading to total system compromise, data loss, or unrestricted access.


## 2. Medium/High Vulnerability: Path Traversal and Bypass in Restricted Path Checks

**Severity:** Medium/High

**Location:** `contop-server/core/dual_tool_evaluator.py` in `_path_referenced()`.

**Description:**
The application prevents access to sensitive files and directories (like `/etc/passwd` or `C:\Windows`) by checking if the restricted path strings are present in the requested file paths or commands. The implementation of `_path_referenced(command, path)` relies on simple substring matching (e.g. `path in command` or `path.lower() in command.lower()`).
This naive string matching does not resolve paths and is highly susceptible to path traversal and normalization bypasses.

**Impact:**
An attacker or malicious LLM can easily bypass the restricted paths check. For example, if `/etc/passwd` is restricted, an attacker could access it by requesting `/etc//passwd`, `/etc/./passwd`, or `/tmp/../etc/passwd`. Because the exact string `/etc/passwd` is not present, the `DualToolEvaluator` will classify the command as `host` (safe), granting the agent unauthorized read/write access to sensitive files.

## Recommendation

**Is this application safe to use as a secure remote desktop application?**

**No.** In its current state, Contop is **unsafe** to use.

The application explicitly advertises sandboxed execution for destructive and dangerous commands. However, due to the critical vulnerability in `DockerSandbox._fallback_run()`, if Docker fails or is missing, the "sandboxed" command will execute directly on the host machine. This means that an explicit security feature is completely broken, giving a false sense of security while actively executing the most dangerous commands on the host system without restriction.

Furthermore, the naive string matching for restricted paths allows arbitrary path traversal, making the "Restricted path isolation" feature trivially bypassable.

Until the Docker sandbox fallback is either removed (so it fails safely by refusing to run the command) or redesigned, and until the restricted path checks are robustly implemented using path resolution (like `os.path.abspath`), the application leaves the user's desktop highly vulnerable to arbitrary code execution, privilege escalation, and data exfiltration.
