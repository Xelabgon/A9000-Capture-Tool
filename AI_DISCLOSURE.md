# AI development disclosure

A9000 Capture Tool was developed with substantial assistance from **OpenAI Codex (ChatGPT)**. The project maintainer defined the goals, supplied A9000 hardware observations and capture files, ran the software on Windows, and gave feedback that guided the changes. Codex wrote and revised much of the application code, tests, and documentation in response.

This disclosure describes the development process. It does not mean that OpenAI endorses the project, maintains it, or has verified every behavior. The software should be reviewed and tested like any other open-source project, especially when changing USB and firmware code.

Some files in `vendor/wifit3/` are adapted from the separate [wifit3 project](https://github.com/derv82/wifit3); they should not be described as original Codex work. The bundled MediaTek firmware is also third-party material. Their attribution and license information are listed in the [README](README.md) and the license files included with the project.

This document is a disclosure, not a license or a rule requiring contributors to use or avoid AI tools. See [LICENSE](LICENSE) for the application's license.
