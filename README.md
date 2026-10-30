# Windows Firewall Dashboard

A local, read-only dashboard for inspecting Windows firewall policy, listening
ports, installed services, and the evidence connecting them.

The dashboard brings firewall rules and their collected restrictions into a
searchable browser interface. Its service assessment helps distinguish a rule
that names a service from a rule that merely matches an executable path, and
shows where shared processes make endpoint ownership ambiguous. It supports
inspection and informed review; it provides no rule or service controls.

## Start the dashboard

Requirements:

- Windows with the firewall, networking, and service commands used by the
  [PowerShell collector](collect.ps1).
- Python 3 and either Windows PowerShell or PowerShell 7 on `PATH`. The server
  prefers `pwsh` when both PowerShell executables are available.
- A modern browser. No Python packages, JavaScript packages, or build step are
  required to run the application.

Run [Start-Dashboard.cmd](Start-Dashboard.cmd), or open a terminal in this
directory and run:

```powershell
python server.py
```

The launcher opens `http://127.0.0.1:8765`. Click **Refresh settings** to collect
a snapshot. Collection is manual and can take up to three minutes. Close the
terminal or press **Ctrl+C** to stop the server.

Use another port or suppress automatic browser opening with:

```powershell
python server.py --port 8766 --no-browser
```

For administrative visibility, open a terminal as administrator and run the
same command. The dashboard does not elevate itself. A standard-user session
can still read much of the firewall configuration; command failures appear in
**System & collection**.

## Inspect the evidence

| View | What it shows |
| --- | --- |
| **Firewall rules** | Searchable rules, enabled state, direction, action, profiles, ports, and addresses. Select a name to inspect all collected conditions. |
| **Services & rule assessment** | All collected Win32 services, including stopped services, with accounts, executable paths, dependencies, candidate rules, and PID-associated endpoints. |
| **Listening ports** | TCP listeners and UDP endpoints, process names, process IDs, and loopback, wildcard, or interface bindings. |
| **Review items** | Conditions worth examining, including some public-profile exceptions and blocked-traffic logging settings. These are review candidates, not vulnerability findings. |
| **System & collection** | Active networks, firewall services, adapters, registered firewall providers, IPsec rules, and collection errors. |

The service view initially prioritizes running services, automatic startup,
and services with associated enabled inbound allow rules. Select **All
services** to see the full collected inventory.

Service-specific rule filters and executable-path candidates are separate.
An executable candidate is included only when the rule has no specific
service restriction. Dependencies show relationships reported by Windows;
they do not establish whether a service is necessary for a particular user.

## Privacy and local operation

The Python server binds to IPv4 loopback, `127.0.0.1`. It checks the request
host and browser origin, rejects cross-site requests, and serves an explicit
allowlist of application files. The frontend uses local scripts and styles,
with no external application assets or analytics configured.

Collection reads firewall profiles, rules and filters, network profiles,
adapters, services, process names, TCP listeners, UDP endpoints, registered
firewall providers, and IPsec rules. It does not change firewall policy,
services, profiles, or rules. Collection occurs only when **Refresh settings**
is requested. The server also exposes the current in-memory snapshot at
`/api/data` to permitted local requests.

**Collected data can identify a machine or its user.** Network names, service
accounts, application paths, firewall restrictions, addresses, and error
messages may contain sensitive information. The application displays those
values as evidence and does not automatically anonymize them.

Snapshots stay in the server's memory and are discarded when it stops. The
server logs request paths and statuses to its terminal, rather than snapshot
contents. Information already displayed in an open browser page remains
visible there until that page is closed or reloaded.

This repository contains application source and synthetic association tests.
The original machine screenshots and collected snapshots are excluded. The
[.gitignore](.gitignore) covers common captures, exports, local environment
files, logs, and caches. Review file contents and screenshots before sharing;
ignore patterns cannot recognize every form of private data.

## Interpretation limits

- Collection is a sequence of reads, rather than an atomic system capture.
  Service state, processes, and sockets may change between reads.
- Command errors mark a snapshot as partial. Empty results do not establish
  that a category is absent. A failed refresh retains the previous displayed
  snapshot and identifies it as previous data.
- A service or executable association does not prove that a rule applies to
  an observed socket. Protocol, ports, profiles, addresses, package, user,
  interface, dynamic restrictions, and enforcement status still matter.
- Shared-host process IDs cannot assign an endpoint to an individual service.
  Listening or binding locally does not establish remote reachability.
- Executable parsing is lexical. It does not verify file existence, the
  resolved image, a publisher, a digital signature, or a default Windows rule.
  A Windows-directory path is a path association only.
- Default-rule status stays **Unverified - no matching baseline** because no
  matching baseline is supplied. Windows operating necessity and the user's
  usage requirements remain unresolved.
- Router forwarding, remote reachability, a separate Hyper-V firewall, and a
  complete Windows Filtering Platform inventory are outside this collector.

## Source map

| File | Responsibility |
| --- | --- |
| [server.py](server.py) | Python standard-library HTTP server, request checks, in-memory snapshot, and PowerShell subprocess invocation. |
| [collect.ps1](collect.ps1) | Read-only Windows collection and JSON serialization, with errors recorded by section. |
| [index.html](index.html) | Dashboard views, filters, tables, and detail dialog. |
| [app.js](app.js) | Refresh flow, firewall and system views, filtering, and rule details. |
| [services.js](services.js) | Service and executable associations, dependency evidence, shared-host handling, and service rendering. |
| [style.css](style.css) | Dashboard layout and presentation. |
| [Start-Dashboard.cmd](Start-Dashboard.cmd) | Windows launcher that runs the server from its own directory. |
| [test_associations.js](test_associations.js) | Synthetic checks for the service-association logic. |

The browser requests the current cache with `GET /api/data`. A manual refresh
sends `POST /api/refresh`; the server runs `collect.ps1`, parses its JSON,
updates the in-memory cache, and returns the snapshot for rendering. A lock
prevents concurrent collection through this server.

## Development and checks

Node.js is optional for development checks and is not a runtime dependency.
Run the existing association test with:

```powershell
node test_associations.js
```

The test covers specific-service filters, executable candidates, shared
processes, stopped services, dependency evidence, and path-origin boundaries.
It uses synthetic values and does not collect system information.

JavaScript syntax can be checked with:

```powershell
node --check app.js
node --check services.js
node --check test_associations.js
```

These checks do not prove that every live collector succeeds, that firewall
rules are effective, or that the dashboard establishes a security baseline.
When changing collection or assessment logic, keep unavailable information,
observed associations, and verified conclusions distinct. Review any new
fixtures and documentation for machine identifiers before committing them.

No standalone project license file is currently included.
