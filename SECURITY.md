# Security Policy

## Supported Versions

This project is currently maintained on the latest published version only.

| Version | Supported |
|---|---|
| Latest | Yes |
| Older versions | No |

## Reporting a Vulnerability

If you believe you have found a security issue in Integrity Monitor, please do **not** open a public issue with exploit details.

Instead, report it privately with:

- a clear description of the issue
- affected version
- steps to reproduce
- expected vs actual behavior
- any proof-of-concept details that help confirm the issue

## What to Include

Please include as much of the following as you can:

- operating system and version
- Python version
- exact command or workflow used
- relevant config/profile settings
- sample file/folder structure if relevant
- logs or tracebacks, if any
- whether the issue affects:
  - hashing
  - baselines
  - manifests
  - watch mode
  - reports
  - profile handling
  - file parsing / JSON loading

## Response Approach

Good-faith reports will be reviewed and triaged as time allows.

The general process is:

1. confirm the report
2. assess impact and scope
3. prepare a fix if valid
4. publish the fix in a future update
5. credit the reporter if appropriate and requested

## Scope

This repository is a local terminal application focused on file integrity workflows. The most relevant security issues are likely to involve:

- unsafe file handling
- incorrect verification behavior
- corrupted manifest/baseline handling
- path traversal or path handling issues
- unsafe report or profile loading behavior
- denial-of-service style crashes from malformed input data

## Out of Scope

The following are generally out of scope unless they cause a real security impact in this project:

- minor usability issues
- feature requests
- purely cosmetic issues
- environment-specific packaging problems without security impact
- third-party package issues that are not specific to this project

## Public Disclosure

Please allow reasonable time for verification and a fix before sharing full public details.
