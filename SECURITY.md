# Security Policy

zmailok is a new project. If you find a security vulnerability, do NOT open a public issue.

Email: info@zophos.org
make sure to put "Security issue :" in title.

I will respond within 48 hours. I will credit you in the changelog if you want.

## What counts as a vulnerability

- Remote code execution
- DNS rebinding or SSRF via crafted domain input
- Any way to make the binary crash on untrusted input (DoS)
- Any way to exfiltrate data (there shouldn't be any — the tool only does outbound DNS lookups)

## What does NOT count

- "It doesn't check X" (that's a feature request, open an issue)
- "The score is wrong for my domain" (open an issue with the domain name)   
