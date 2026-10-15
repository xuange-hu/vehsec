# Security Policy

## Scope

This policy covers **vulnerabilities in `vehsec` itself** (the toolkit's code,
dependencies, and the Docker labs).

`vehsec` is a research and teaching toolkit. It is **not** a vulnerability
disclosure channel for vehicle manufacturers — if you find a flaw in a real vehicle,
report it directly to that manufacturer (and, where applicable, to your national
CERT or an industry ISAC).

## Reporting a vulnerability in vehsec

Please **do not open a public issue** for security problems. Instead:

1. Use GitHub's private reporting: *Security* → *Report a vulnerability* on
   <https://github.com/xuange-hu/vehsec/security/advisories>, or
2. Email the maintainer with the details below.

Include:
- affected version / commit,
- steps to reproduce (a `python-can virtual` repro is ideal — no hardware needed),
- impact and, if relevant, a suggested fix.

You can expect an acknowledgement within 72 hours and a status update within 7 days.
We will credit you in the fix release unless you prefer to stay anonymous.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ current |

## Use of this software

`vehsec` is intended for **authorized security research, education, and testing on
equipment you own**. Using it against vehicles or networks without authorization may
be illegal in your jurisdiction. The maintainers accept no liability for misuse, and
will not provide support for unauthorized testing.

If you are a vehicle manufacturer or supplier and believe this project is being used
against your products, please contact us — we will cooperate and, where appropriate,
remove offensive material.
