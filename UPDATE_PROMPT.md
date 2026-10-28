# Prompt for an AI assistant: add products or update everything

> Copy everything below the line into an AI coding assistant that has **shell access, web access and ideally a headless browser** (e.g. Claude Code with Playwright), opened in your fork of this repository. Replace the `TASK` block first.

---

You are maintaining `README.md` in this repository: a status overview of Node2Shell / Broccoli2Shell (CVE-2026-111497) for enterprise readers. `VERIFICATION.md` is the provenance log and `CHANGELOG.md` the history.

## TASK

<!-- Pick one and delete the other: -->
- **Add:** `<product / vendor 1>`, `<product / vendor 2>`, … — find out whether they ship Node.js or a Brotli decoder, what the vendor says, and add them to the right section.
- **Update everything:** re-check every row against its source, update statuses, add new vendor statements and fixes published since the last update.

## Rules (not optional)

1. **Primary sources only.** Count only the vendor's own advisory/PSIRT page, the distribution's tracker or errata, or official machine-readable feeds. News sites, blogs, aggregators and the NCSC-NL list are *leads* for finding sources, not proof. If you only have a secondary source, mark the row **not verified**.
2. **Read raw text, never summaries.** Do not use a fetch tool that returns an AI summary. Download with `curl` (or a headless browser for JavaScript pages), convert to text and `grep` for the exact strings: version numbers, advisory IDs, dates. Summaries have produced wrong advisory IDs, wrong exploitation claims and merged headings into product names.
3. **Quote, don't infer.** Write what the vendor states ("under investigation", "not affected", "fixed in X"). No "probably not affected". Absence of a statement is not "not affected".
4. **Real timestamps.** Run `date -u` when you check each source and record that time. Never estimate or round a check time into the future.
5. **Distinguish three states:** *statement found*; *checked, nothing found (UTC time, where you looked)*; *could not check (reason: login, bot protection, 403, page not rendering)*.
6. **Log every claim** in `VERIFICATION.md` as a table row: claim | source URL | UTC time | method (raw / browser / JSON) | verbatim evidence.
7. **Markdown:** put every package version in backticks — Debian versions contain `~`, which GitHub otherwise renders as strikethrough. Write "approx." instead of "~".
8. **Keep the structure:** AI-generated warning banner at the top; status line (date + UTC time + update number) first; current status only in `README.md`. Section 1 holds network/security and other enterprise vendors (and managed platforms such as Vercel), section 2 enterprise Linux distributions and enterprise repositories (Remi), section 3 upstream components that bundle the decoder. **Out of scope** (enterprise only): hobby/self-hosting products, NAS and SMB products, desktop/rolling/testing distributions (Fedora, Arch, Gentoo, openSUSE Tumbleweed, Debian testing/unstable), desktop-only applications. Do not delete verified in-scope rows; update them. Put the history entry at the **top** of `CHANGELOG.md`, not in the README.
9. **Keep the README short.** It holds the current state only: no change history inside rows ("moved from …", "earlier: …", corrections), no per-source check times outside the status line (they go in `VERIFICATION.md`), not-affected lists as a selection plus "full list: advisory". Aim for at most about 150 words per table cell.
10. **Node.js checks:** never tell readers to rely on `process.versions.brotli` (patched builds still report 1.2.0); compare `node --version` with the fixed releases.
11. **Re-check the "Key facts"**, especially exploitation: CISA KEV, CISA SSVC (CVE record), vendor threat-intel reports. Then update "Known gaps".

## Useful machine-readable sources

| What | Where |
|---|---|
| NVD scores | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| CISA SSVC (ADP) | `https://cveawg.mitre.org/api/cve/<CVE>` → `containers.adp` |
| Red Hat per-stream status + all RHSAs | `https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-111497.json` |
| Rocky Linux errata | `https://apollo.build.resf.org/api/v3/advisories/?page=N&limit=100` (filter parameters are ignored: page through and select by synopsis) |
| Oracle Linux | `https://linux.oracle.com/cve/<CVE>.html` (ELSA numbers usually mirror RHSA numbers) |
| Amazon Linux | `https://explore.alas.aws.amazon.com/<CVE>.html` |
| Debian / Freexian ELTS | `https://security-tracker.debian.org/tracker/<CVE>`, `https://deb.freexian.com/extended-lts/tracker/<CVE>` |
| Ubuntu | `https://ubuntu.com/security/<CVE>` and the USN pages |
| SUSE | `https://www.suse.com/security/cve/<CVE>.html` (use the *patchname*, not the TID) |
| Docker Official Image | `https://hub.docker.com/v2/repositories/library/node/tags/<tag>` |
| GitHub / OSV advisories (PyPI, npm, Go, Maven) | `gh api /advisories/<GHSA>`, `https://api.osv.dev/v1/vulns/<ID>` |
| SonicWall PSIRT list | `https://psirtapi.global.sonicwall.com/api/v1/vulnsummary/` |
| Sophos advisories (page often 403) | `https://www.sophos.com/en-us/security-advisories/feed` (RSS) |
| RPM spec of a third-party package | download the SRPM into an empty directory, `rpm2cpio … \| cpio -id`, read the `.spec` (do not build it) |
| Zendesk help centers behind bot protection | `https://<host>/api/v2/help_center/en-us/articles/<id>.json` |
| Leads for missing vendors and bundled copies | `https://broccoli2shell.com/`, oss-security list, the PHP2Shell sweep in `hkoeck/php2shell-status` (vendor list) — leads only |

JavaScript-heavy portals (F5 MyF5, Citrix support, Ivanti hub, Juniper support portal, SonicWall PSIRT, HPE support) usually work in a headless browser: wait until the article text is visible, then read `document.body.innerText`.

Pages behind bot protection (Cloudflare/Akamai: Zabbix forum, Sophos, Broadcom, Akamai, Zendesk help centers) reject headless Chrome because its User-Agent says `HeadlessChrome`. Use a normal, **headed** Chrome on a real desktop session instead; the automatic browser check then usually passes on its own. Do not spoof the User-Agent or solve challenges on someone's behalf. On Linux, if that desktop user has no unlocked login keyring, start Chrome with `--password-store=basic`, otherwise Chrome blocks every page load waiting for a keyring password prompt.

## For each new product, find out

- Does it ship Node.js, link the system libbrotli or bundle its own Brotli decoder? (evidence, ideally from the vendor's own documentation)
- The vendor's statement: affected / not affected / under investigation, with advisory ID, publication and update date
- Affected and fixed versions, workarounds or mitigations exactly as published
- Vendor detection or protection content (IPS/WAF rule IDs), if any
- **Search the vendor's support/knowledge-base portal for the literal CVE ID**, not only the PSIRT or IPS advisory index. Many vendors (Check Point sk…, Quest KACE KB, Broadcom KB, Ivanti KB, Citrix Tech Zone) publish there first and never on the PSIRT list
- Check whether a cited link actually mentions the CVE (aggregator lists sometimes link unrelated posts)

## When you are done

- Update the status line (date, UTC time, update number + 1)
- Match every `"…"` quote in README.md against the text you downloaded in this pass. If a source removed or reworded the text, say so ("removed on …") instead of keeping it as current wording
- Add a `CHANGELOG.md` entry at the top: what changed, what was corrected, what is still not verified
- Report back: a summary of changes plus a list of everything you could **not** verify, with the reason
