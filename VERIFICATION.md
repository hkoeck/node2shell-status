# Verification log

Each claim in [README.md](README.md) was checked against the raw text of its source (curl + HTML-to-text + grep, JSON feeds, or headless-browser `innerText` where noted). Times are UTC from `date -u` runs around each batch. "Could not check" means the source was not readable; it does not mean the vendor has no statement.

## Update 1 checks (28 Oct 2026)

Batches: curl sweep 09:36:15–09:36:32; Rocky Apollo API 09:38:50–09:39:03; upstream sources 09:40:44–09:41:00; ELLIO / oss-security / Go release 09:42:28–09:42:35; browser (F5, Akamai, Sophos, Citrix, Ivanti, Juniper, Check Point) 09:42:50–09:46:25; Sophos RSS / SonicWall API 09:44:19–09:44:22; php.net + Brotli releases API 09:46:39; Node.js source check 09:53:05. Other GitHub API calls (`gh api`) ran 09:39–09:42; the Ruby gem comment was re-read during the quote check (09:46–09:49).

| Claim | Source | Time (UTC) | Method | Evidence (verbatim or field) |
|---|---|---|---|---|
| Bug mechanism, Node.js fixed versions, "high" | nodejs.org/en/blog/vulnerability/october-2026-security-releases | 09:36 | raw | "An invalid block switch was reported as a temporary need for more input instead of a permanent format error …"; "Node.js v22.23.4", "v24.22.1", "v26.12.1"; "End-of-Life versions are always affected" |
| Brotli 1.0.10 / 1.1.1 / 1.2.1 released 21 Oct | api.github.com repos/google/brotli/releases | 09:46 | JSON | `v1.2.1 2026-10-21T19:27:34Z`, `v1.1.1 …19:27:20Z`, `v1.0.10 …19:26:58Z` |
| Fix commit dated 27 Feb 2026 | api.github.com repos/google/brotli/commits/0ed4268 | 09:41–09:42 | JSON | author date `2026-02-27T13:10:32Z`, "Detect and report invalid stream earlier." |
| CNA ranges, CVSS 4.0 9.2, CWE-787/252 | cveawg.mitre.org/api/cve/CVE-2026-111497 | 09:36 | JSON | `1.0.3 <1.0.10`, `1.1.0 <1.1.1`, `1.2.0 <1.2.1`; `baseScore 9.2 CRITICAL` |
| CISA SSVC Exploitation active | same, `containers.adp` CISA-ADP | 09:36 | JSON | `{"Exploitation":"active"}`, timestamp `2026-10-23` |
| KEV entry | cisa.gov known_exploited_vulnerabilities.json | 09:36 | JSON | catalogVersion `2026.10.27`; dateAdded `2026-10-27`; dueDate `2026-11-10`; forensicTriage `No` |
| NVD | services.nvd.nist.gov API 2.0 | 09:36 | JSON | published `2026-10-22T14:17:37`; "Undergoing Analysis" |
| ELLIO in-the-wild, x86-64, `process.versions.brotli` | ellio.tech/en/blog/node2shell-cve-2026-111497-rce-on-stock-nodejs-builds/ | 09:42 | raw | "Update, 26 October 2026. ELLIO sensors have recorded CVE-2026-111497 exploit traffic in the wild …"; "reproduced it on x86-64 against four targets"; "process.versions.brotli reports 1.2.0 on a patched build and on a vulnerable one" |
| Imperva RCE on 24.22.0 arm64 | imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/ | 09:40 | raw | "official Node.js 24.22.0 Linux arm64 image"; "We tested Express 5.0.0–5.3.0 and body-parser 2.0.0–2.3.0 … execution took multiple attempts in our setup." |
| Red Hat: no public, reliable RCE PoC; Important 8.1, per-stream status, RHSAs | security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-111497.json (current_release_date `2026-10-28T08:57:37`) | 09:36 | JSON | note "there is no public, reliable remote code execution proof-of-concept"; `known_affected` EL8 `nodejs:24`, EL9 `nodejs:24`/`nodejs:26`, `dotnet8.0` EL8/9/10; `known_not_affected` `nodejs:22` EL8/9, EL10 `nodejs22/24/26`; vendor_fix RHSA-2026:90501/90495/90449 (26 Oct), 90888–90893, 90914 (27 Oct), 87420 (Hardened Images) |
| RHSB status | access.redhat.com/security/vulnerabilities/RHSB-2026-015 | 09:36 | raw | "Updated October 27, 2026, 17:37"; "Ongoing" |
| Palo Alto row | security.paloaltonetworks.com/CVE-2026-111497 | 09:36 | raw | Published 2026-10-26, Updated 2026-10-28; table `>= 12.1.4-h13 (ETA: 10/29)`, `>= 12.1.10-h3 (ETA: 10/30)`, `>= 11.2.4-h23 (ETA: 10/30)`; "The only exception is 11.2.10-h16 which only includes the fix for PHP vulnerabilities"; "Panorama (virtual and M-series) is not impacted."; "Palo Alto Networks is not aware of any malicious exploitation of this issue." |
| Cisco row | sec.cloudapps.cisco.com … cisco-sa-oct2026-node-js-Jj3SQ19u | 09:36 | raw | "2026 October 27 21:30 GMT", "Version 1.0: Interim"; 9 priority + 90 further products (13 category rows excluded); "aware that proof-of-concept exploit code is available"; "not aware of any malicious use" |
| Fortinet row | fortiguard.fortinet.com/psirt/FG-IR-26-187 | 09:36 | raw | "CVE-2026-111497 - (high)"; Updated Oct 27, 2026; Component GUI; Severity Critical; CVSSv3 9.8; Known Exploited No; Virtual Patch No; 47 under investigation, 22 not impacted; FortiADC, FortiDeceptor, FortiPresence in both lists |
| F5 row | my.f5.com/manage/s/article/K000163902 | 09:42–09:46 | browser | "Published Date: Oct 26, 2026Updated Date: Oct 28, 2026"; NGINX Plus / Open Source "Not vulnerable"; others "**"; "No NGINX Plus Brotli module update is required for this decoder-only vulnerability." |
| F5 Node.js article | my.f5.com/manage/s/article/K000163874 | 09:42–09:46 | browser | "CVE-2026-111497 was previously included in this article, but has since been moved to its own article" |
| Check Point IPS | advisories.checkpoint.com … cpai-2026-15802.html | 09:36 | raw | "24 Oct 2026", "Critical", "R82, R81, R80, R77, R75", "Web Server Enforcement Violation" |
| Sophos: nothing found | sophos.com/en-us/security-advisories/feed (page itself 403 / HTTP2 error) | 09:44 | RSS | newest titles eMudhra, PHP2Shell; no "brotli" / "111497" |
| SonicWall: nothing found | psirtapi.global.sonicwall.com/api/v1/vulnsummary/ | 09:44 | JSON | newest SNWLID-2026-0018 (14 Oct); no match for 111497 / brotli |
| Juniper: nothing found | supportportal.juniper.net global search "CVE-2026-111497" | 09:42–09:46 | browser | 5 results, all unrelated JSA/TSB articles |
| Ivanti: nothing found | hub.ivanti.com searchallcontent "CVE-2026-111497" | 09:42–09:46 | browser | only community questions (EPMM / Sentry, vADC), no Ivanti answer |
| Citrix, Check Point KB, Akamai: could not check | support.citrix.com search; support.checkpoint.com/results/search; akamai.com blog | 09:42–09:46 | browser | Citrix page rendered no results list; Check Point 404; Akamai "Access Denied" |
| Vercel | vercel.com/kb/bulletin/node-js-security-advisory | 09:36 | raw | "Vercel deployed WAF rules the same day …"; "Node.js does not decode Brotli data on its own." |
| Debian | security-tracker.debian.org CVE / DSA-6582-1 / DLA-4855-1 | 09:36 | raw | trixie (security) `1.1.0-2+deb13u1` fixed; bookworm (security) `1.0.9-2+deb12u1` fixed; note "nodejs and python-brotlicffi use system provided brotli library" |
| Freexian ELTS | deb.freexian.com/extended-lts/tracker/CVE-2026-111497 | 09:36 | raw | buster `1.0.7-2+deb10u2` ELA-1861-1; bullseye `1.0.9-2+deb11u1` ELA-1861-1; stretch "(unfixed)" end-of-life |
| Ubuntu | ubuntu.com/security/CVE-2026-111497, USN-8956-1 | 09:36 | raw | priority Medium; fixed versions per release; focal nodejs "Vulnerable"; "nodejs on focal uses the vendored brotli"; USN dated 26 October 2026 |
| AlmaLinux | errata.almalinux.org ALSA-2026:90501 / 90495 / 90449 | 09:36 | raw | release dates 2026-10-26 / 2026-10-27 / 2026-10-27; same NVRs |
| Rocky Linux: none yet | apollo.build.resf.org/api/v3/advisories pages 1–3 | 09:38–09:39 | JSON | newest `2026-10-27T12:08:55Z`; no synopsis/description matching brotli, nodejs or 111497; RLSA-2026:90495 page: "Requested advisory not found" |
| Oracle Linux | linux.oracle.com/cve/CVE-2026-111497.html | 09:36 | raw | ELSA-2026-500512/-90501 (OL8 brotli), -500513 (OL9 brotli), -500514/-90449 (OL10 brotli), -500519/-500520 (OL8 nodejs), -500517/-500518 (OL9 nodejs), -500516 (OL10 nodejs22), -500515 (OL10 nodejs24) |
| Amazon Linux | explore.alas.aws.amazon.com/CVE-2026-111497.html | 09:36 | raw | AL2023 brotli ALAS2023-2026-3334, nodejs24 ALAS2023-2026-3330 (2026-10-24); AL2027 ALAS2027-2026-244/-245; AL2023 nodejs, nodejs20 "No Fix Planned"; nodejs22 "Not Affected" |
| SUSE | suse.com/security/cve/CVE-2026-111497.html | 09:36 | raw | "Overall state of this security issue: Pending"; QA list libbrotli `1.0.7-150200.3.8.1`, nodejs22 `22.23.4-150700.3.21.1` / `-150600.13.27.1`, nodejs24 `24.22.1-150700.15.21.1`; status table "In progress" for 16.0 / 16.1 / Micro 6.0–6.2; "Affected" openSUSE Leap 16.0, SLE Micro 5.3 |
| Remi php-brotli builds against system lib | rpms.remirepo.net/SRPMS/php-brotli-0.21.1-1.remi.src.rpm (unpacked with rpm2cpio, not built) | 09:39–09:40 | spec | `%bcond_without      libbrotli`; `BuildRequires: brotli-devel >= 0.6.0`; `# Use the system library` / `rm -r brotli`; repoview changelog 2026-10-25 "update to 0.21.1" |
| Python | api.github.com/advisories/GHSA-9v8h-qqgm-4m35; api.osv.dev PYSEC-2026-4322 / -4323 | 09:36–09:40 | JSON | brotli `>= 1.0.3, < 1.2.1`, brotlicffi `>= 1.0.3, < 1.2.1.0` |
| .NET | github.com/dotnet/announcements/issues/494 | 09:40 | raw | "opened on Oct 25, 2026"; 8.0.33, 9.0.22, 10.0.14, 11.0.0-rc.3; ".NET Framework is not affected." |
| Envoy | api.github.com envoyproxy/envoy security-advisories GHSA-3wvj-j6qm-62mr | 09:41–09:42 | JSON | patched `v1.40.0, v1.39.3, v1.38.6, v1.37.8, v1.36.12`; "Envoy deployments that have Brotli decompressor configured." |
| Istio | istio.io/latest/news/security/istio-security-2026-007/ | 09:41–09:42 | raw | "CVE-2026-111497 (GHSA-3wvj-j6qm-62mr)"; upgrade to 1.31.2 / 1.30.6 / 1.29.9 |
| PHP Windows builds | php.net/archive/2026.php | 09:46 | raw | "PHP 8.5.12-1, 8.4.27-1, 8.3.36-1 and 8.2.35-1. These builds include Brotli 1.2.1, which fixes CVE-2026-111497"; "reached through the cURL extension when automatic HTTP response decompression is enabled" |
| PECL brotli 0.21.1 | api.github.com repos/kjdev/php-ext-brotli/releases | 09:41–09:42 | JSON | `0.21.1` published `2026-10-24T23:49:20Z`, "Update brotli submodule to v1.2.1" |
| Ruby gem | api.github.com repos/miyucy/brotli/issues/64/comments | 09:41–09:42 | JSON | "released as brotli 0.9.1, which bundles Brotli 1.2.1" |
| Brotli4j | api.github.com repos/hyperxpro/Brotli4j/releases | 09:41–09:42 | JSON | v1.24.0 (2026-10-24) "Upgrade brotli dependency to 1.2.1"; GHSA-x524-jrqf-vwq6 |
| Node.js bundled version string | api.github.com repos/nodejs/node contents `deps/brotli` at `v24.22.1` | 09:53 | JSON | `version.h`: `BROTLI_VERSION_MINOR 2`, `BROTLI_VERSION_PATCH 0`; `dec/decode.c` contains `BLOCK_SWITCH` (patched) |
| Go port | api.github.com repos/andybalholm/brotli tag v1.2.7 | 09:41–09:42 | JSON | tag commit 2026-10-23 "This is a port of https://github.com/google/brotli/commit/0ed4268a" |
| Bun | bun.com/blog/bun-v1.4.4 | 09:40–09:42 | raw | "This release includes security fixes for …"; list includes "Brotli"; no CVE ID |

## Draft input

Update 1 started from a user-supplied draft (PDF, "status snapshot 28 October 2026, approx. 10:30 UTC", created 09:24 UTC). The draft was used as a list of leads only; every row above was re-read at the source. Deviations are listed in [CHANGELOG.md](CHANGELOG.md).
