# zmailok

Email deliverability checker. One command, one score, one fix list.

```console
$ zmailok check example.com
example.com — 70/100

  ✓   SPF          v=spf1 -all
  ✓   DKIM         selector s1
  ✓   DMARC        p=reject pct=100
  ✓   DMARC policy reject
  ✗   PTR          not found
  ✗   rDNS         not found
  ✗   MX           not found
  ✓   Blacklist    clean

  Score: 70/100 — NOT OK — 3 issues found

  Fixes:
  1. Add PTR: ask your hosting provider to set reverse DNS for your sending IP
  2. Fix rDNS: make the PTR hostname resolve back (A record) to the same sending IP
  3. Add MX: publish at least one MX record on example.com pointing to your mail server
```

The checker runs **on your own machine**. It is free, has no limits, needs no account and sends nothing to anyone but your DNS resolver. Optional hosted monitoring (paid) is described [below](#hosted-monitoring-optional-paid).

## Install

You need [Rust](https://rustup.rs). Then:

```sh
cargo install zmailok
```

## Check a domain

```sh
zmailok check example.com
```

| Option | What it does |
| --- | --- |
| `--json` | Print the full result as JSON (for scripts and CI) |
| `--ip 203.0.113.5` | The IPv4 address of your mail server, used for the PTR, rDNS and blacklist checks (see [Good to know](#good-to-know)) |
| `--dkim-selector mail2024` | A DKIM selector to try first, in addition to the built-in list |

### What is checked

The score is out of 100:

| Check | Points | Passes when |
| --- | --- | --- |
| SPF | 15 | the domain publishes a `v=spf1` record (`include:` records are followed, up to 10) |
| DKIM | 20 | a key is published for one of the selectors `s1`, `s2`, `default`, `google`, `k1`, `selector1`, `selector2`, `_domainkey` (or the one you pass with `--dkim-selector`) |
| DMARC | 15 | `_dmarc.<domain>` has a valid `v=DMARC1` record with a `p=` policy |
| DMARC policy | 10 | the policy is not `none` |
| PTR | 10 | the sending IP has a reverse DNS name |
| rDNS | 10 | that name resolves back to the same IP |
| MX | 10 | the domain has a mail server (a "null MX" does not count) |
| Blacklist | 10 | the IP is not listed on Spamhaus ZEN, Barracuda or SORBS |

Every failed check adds one line to the fix list.

**Checks that do not apply are left out.** PTR, rDNS and the blacklists look at one mail server's IP address (see below). When there is no such address to look at, those 30 points are left out and the score is scaled, so a domain that passes everything that applies to it gets 100. The report says when this happened.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | score is 80 or higher |
| `1` | score is below 80 |
| `2` | the tool could not run: invalid domain, domain does not exist, no network, bad option |

So `zmailok check example.com || echo "deliverability problem"` and CI checks work as you would expect.

### Good to know

- **Which IP is checked?** PTR, rDNS and the blacklists look at one IP address, and which one depends on the domain:
  - **Sends through a service like Google Workspace, Microsoft 365, SendGrid, Amazon SES, Mailgun or Mailchimp** (zmailok reads this from the `include:` entries of the SPF record, and lists what it found as "Also sends through"): these checks are **skipped**. The domain's A record is just its website, and those services control their own mail servers.
  - **No such service in the SPF record:** the domain's own **A record** is used.
  - **You pass `--ip <address>`:** that address is checked, always. Use it for your own mail server, including when you send through a service *and* run a server of your own.
- **IPv4 only.** IPv6 addresses are not checked.
- **DKIM selectors are arbitrary.** A domain can use any name, so a missing key may just mean a selector zmailok did not try. Find yours in a message header (`DKIM-Signature: ... s=<selector>`) and pass it with `--dkim-selector`.
- **Timeouts.** Each DNS lookup waits at most 5 seconds. A lookup that times out counts as "not found", so run it again if your network is unreliable. zmailok ignores DNS servers from your system settings that do not answer, so a stale entry on an unused network adapter does not slow it down.
- **Blacklists** are queried through your normal DNS resolver. Spamhaus refuses queries from some public resolvers (such as 8.8.8.8). zmailok does not treat that refusal as a listing, but it also cannot see a listing in that case.

## Hosted monitoring (optional, paid)

Nothing above needs an account. If you would rather not run checks yourself, a hosted service checks your domains **every 6 hours** and **emails you when a score drops by more than 10 points**. It costs $5/month for up to 5 domains.

```sh
zmailok login                  # log in with GitHub: you get a code, approve it in the browser
zmailok upgrade                # prints the checkout link for the subscription
zmailok monitor add example.com
zmailok monitor list
zmailok monitor remove example.com
zmailok logout
```

- **Login** uses GitHub's device flow, so nothing is redirected: the terminal shows a code, you enter it at <https://github.com/login/device>, and the terminal logs in. Only your GitHub account id and your primary verified email address are kept.
- **Your login** is saved in `~/.config/zmailok/token` (`%APPDATA%\zmailok\token` on Windows), readable only by you. `zmailok logout` revokes it and deletes the file.
- Run `zmailok monitor add` and you immediately see the current score; the service's own first check follows within 6 hours.

| Environment variable | Purpose |
| --- | --- |
| `ZMAILOK_TOKEN` | Use this login token instead of the saved file (servers, CI) |
| `ZMAILOK_CONFIG_DIR` | Where the login token is saved |
| `ZMAILOK_API` | Another service address (must be `https://`; `http://localhost` is allowed for development) |

## Privacy

`zmailok check` only talks to your DNS resolver. The monitoring commands talk to `api.zmailok.com`, and nothing else is ever sent there.

## Development

```sh
cargo build
cargo test      # parsing, scoring and CLI logic; no network needed
```

The checker is a library as well as a command: `zmailok::dns::check`, `zmailok::score::compute` and `zmailok::output::print_report` are public. The hosted service is a separate, private project.

## License

Apache-2.0, see [LICENSE](LICENSE).
