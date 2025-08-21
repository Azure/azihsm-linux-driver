# Security

## Security Policy

Microsoft takes the security of our software products and services seriously, including all open source code repositories managed through our GitHub organizations.

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them to the Microsoft Security Response Center (MSRC) at [https://msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report).

If you prefer to submit without logging in, send email to [secure@microsoft.com](mailto:secure@microsoft.com). If possible, encrypt your message with our PGP key; please download it from the [Microsoft Security Response Center PGP Key page](https://www.microsoft.com/en-us/msrc/pgp-key-msrc).

You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message. Additional information can be found at [microsoft.com/msrc](https://www.microsoft.com/msrc).

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

* Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
* Full paths of source file(s) related to the manifestation of the issue
* The location of the affected source code (tag/branch/commit or direct URL)
* Any special configuration required to reproduce the issue
* Step-by-step instructions to reproduce the issue
* Proof-of-concept or exploit code (if possible)
* Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Security Considerations for Azure Integrated HSM Linux Driver

This driver provides low-level access to Azure Integrated HSM hardware. Users and system administrators should be aware of the following security considerations:

* **Privileged Access**: This kernel driver requires root privileges to load and operate
* **Hardware Security**: The driver facilitates communication with hardware security modules - ensure proper physical security of the systems where this driver is deployed
* **Driver Loading**: Only load this driver on trusted systems with verified kernel integrity
* **Updates**: Keep the driver updated with the latest security patches and versions

## Contact

For general questions about this project, please contact **AziHSM_OSS@Microsoft.com**.

For security-related issues, please follow the reporting process outlined above.