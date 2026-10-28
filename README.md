# Node2Shell / Broccoli2Shell (CVE-2026-111497) – Enterprise Vendor and Distribution Status

> [!WARNING]
> **AI-generated content.** This document was researched and written by an AI assistant (Claude, Anthropic). Statements were checked against the raw text of the linked primary source (HTML/JSON, not summaries) **except where marked as not verified**; provenance is logged in [VERIFICATION.md](VERIFICATION.md). It may still contain errors and goes stale quickly. **Always verify against the vendor source before acting.** No warranty.

**Status:** 28 October 2026, 09:53 UTC (update 1). Sources downloaded 09:36–09:46 UTC; browser-only pages (F5, Ivanti, Juniper) 09:42–09:46 UTC. Could not check: Akamai (HTTP 403), Sophos advisory page (403; RSS feed read instead), Citrix support search (did not render), Check Point support search (404). Per-source times: [VERIFICATION.md](VERIFICATION.md). Change history: [CHANGELOG.md](CHANGELOG.md).

## Key facts

- **The bug:** out-of-bounds write in the Google Brotli C decoder (`c/dec/decode.c`), CWE-787 / CWE-252. Node.js: "An invalid block switch was reported as a temporary need for more input instead of a permanent format error, so the streaming decoder kept appending input bytes to an eight-byte internal buffer." Impact: crash, memory disclosure or remote code execution in any process that decompresses attacker-controlled Brotli data.
- **Affected / fixed:** Brotli 1.0.3 up to 1.2.0; fixed in **1.0.10, 1.1.1, 1.2.1** (released 21 Oct 2026). The upstream fix commit [0ed4268](https://github.com/google/brotli/commit/0ed4268) is dated 27 Feb 2026. Node.js fixed in **22.23.4, 24.22.1, 26.12.1** (21 Oct); end-of-life lines get no fix.
- **Severity:** CNA (Google) CVSS 4.0 **9.2 Critical**; Node.js "high"; Red Hat, Oracle, Amazon: Important / CVSS 3.1 8.1 (AC:H); SUSE CVSS 3.1 8.1; Ubuntu priority Medium.
- **Exploitation:**
  - **CISA KEV:** added 27 Oct 2026, due **10 Nov 2026** (BOD 26-04), forensic triage "No" (catalog 2026.10.27). CISA SSVC (ADP) in the CVE record: Exploitation `active` (23 Oct).
  - **In the wild:** [ELLIO](https://ellio.tech/en/blog/node2shell-cve-2026-111497-rce-on-stock-nodejs-builds/) (update 26 Oct): "ELLIO sensors have recorded CVE-2026-111497 exploit traffic in the wild, carrying the public exploit that we confirmed gets a shell on vulnerable builds."
  - **Shells on stock builds:** [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/) ran code on the official Node.js 24.22.0 Linux arm64 image via `fetch()` and Express / body-parser request bodies ("execution took multiple attempts"). ELLIO reproduced it on x86-64 against four targets.
  - **Contradicting vendor text:** Red Hat still writes "there is no public, reliable remote code execution proof-of-concept". Palo Alto and Cisco PSIRT: not aware of malicious use.
- **Exposure paths:** Node.js `zlib` Brotli APIs and `fetch()` (decodes `br` responses, so a malicious server attacks the client); Express 5.0.0–5.3.0 / body-parser 2.0.0–2.3.0 request parsers (Imperva tested); Python urllib3/requests/aiohttp/httpx when Brotli or brotlicffi is installed; .NET; Envoy/Istio only with the Brotli decompressor; libcurl with automatic decompression; browsers. Vercel: "Node.js does not decode Brotli data on its own."
- **System library vs. bundled copy:** distribution packages often link the system `libbrotli` (Debian, Ubuntu ≥ 22.04, RHEL nodejs:22 and EL10 Node.js, .NET 9+ on RHEL). Upstream Node.js binaries, Python wheels and many appliances carry their own copy, which needs its own update. Either way, running processes keep the old decoder until restarted.

## 1. Network and security vendors

| Vendor | Status |
|---|---|
| **Palo Alto Networks** | [Advisory](https://security.paloaltonetworks.com/CVE-2026-111497) (upd. 28 Oct), CVSS 4.0 9.2, urgency moderate. PAN-OS 11.2 / 12.1 / 12.2 on PA-/VM-Series only with Brotli inspection **and** TLS decryption enabled (Brotli encoding is off by default from 11.2.4); management web UI / API not affected. **Released:** `12.2.4-h1`, `12.1.7-h11`, `11.2.16-h1`, `11.2.13-h4`, `11.2.10-h17`, `11.2.7-h23`. **Due:** `12.1.4-h13` (ETA 10/29), `12.1.10-h3` and `11.2.4-h23` (ETA 10/30). `11.2.10-h16` "only includes the fix for PHP vulnerabilities". Workaround: `set system setting brotli-encoding disable` (check: `show system setting brotli`). Not affected: PAN-OS 11.1 / 10.2, Panorama, Idira self-hosted. Prisma Cloud AppSec Transporter Client fixed in `0.2.9`; SaaS (ADEM, CIE, Prisma AIRS Gateway and others) remediated by PAN. |
| **Cisco** | [cisco-sa-oct2026-node-js-Jj3SQ19u](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u) v1.0 **Interim** (27 Oct 21:30 GMT), covers this CVE plus Node.js CVE-2026-105482 / -105483 / -106069. Vulnerable and not-vulnerable lists still empty. Priority products under investigation: ISE, Catalyst SD-WAN Manager, IOS, IOS XE, IOS XR, NX-OS, ASA, FMC, FTD; 90 more products and services (selection: Catalyst Center, Nexus Dashboard / NDFC, Secure Network Analytics, Secure Workload, ThousandEyes, Umbrella, Webex, Intersight, AppDynamics; full list: advisory). "If a product is not listed within this advisory, Cisco's review indicates that the product is not affected by this vulnerability." Aware of PoC code, not of malicious use. No workarounds. |
| **Fortinet** | [FG-IR-26-187](https://fortiguard.fortinet.com/psirt/FG-IR-26-187) "Multiple Node.js CVEs" (upd. 27 Oct), component GUI, advisory rating Critical / CVSS 3 9.8 (this CVE itself listed as "high"); not known exploited; no virtual patch; no fixed versions yet. Under investigation (selection): FortiOS, FortiProxy, FortiMail, FortiNAC / -F, FortiSIEM, FortiSandbox, FortiSwitch, FortiEDR, FortiSASE, FortiGate Cloud. Not impacted (selection): FortiManager, FortiAnalyzer, FortiClient EMS, FortiAuthenticator, FortiWeb, FortiSOAR. FortiADC, FortiDeceptor and FortiPresence appear in **both** lists on the page. Full lists: advisory. |
| **F5** | [K000163902](https://my.f5.com/manage/s/article/K000163902) (pub. 26 Oct, upd. 28 Oct): BIG-IP (17.x, 21.x), BIG-IQ, BIG-IP Next, F5OS, F5 Distributed Cloud, NGINX One Console, F5 AI Gateway all "**" (still researching). **NGINX Plus and NGINX Open Source: not vulnerable**; the `nginx-plus-module-brotli` package uses the OS Brotli library ("No NGINX Plus Brotli module update is required"; update the OS package). Mitigation: custom Advanced WAF attack signature blocking `Content-Encoding: br` on POST/PUT/PATCH; `/_next/image` URL restriction for Next.js. The other nine Node.js CVEs: [K000163874](https://my.f5.com/manage/s/article/K000163874). |
| **Check Point** | No product statement found. IPS protection [CPAI-2026-15802](https://advisories.checkpoint.com/defense/advisories/public/2026/cpai-2026-15802.html) "Node.js Brotli Remote Code Execution" (24 Oct, Critical) for Security Gateway R82 / R81 / R80 / R77 / R75; log attack name "Web Server Enforcement Violation". Support KB search could not be checked. |
| **Sophos, SonicWall, Juniper, Ivanti** | Checked, nothing found: Sophos advisory RSS (newest items eMudhra CA, PHP2Shell); SonicWall PSIRT list (newest SNWLID-2026-0018, 14 Oct); Juniper support portal search (no matching article); Ivanti hub search (only community questions about EPMM / Sentry and vADC, no Ivanti answer). |
| **Citrix** | Could not check (support search did not render). |
| **Vercel** | [Bulletin](https://vercel.com/kb/bulletin/node-js-security-advisory): "Vercel deployed WAF rules the same day that block the inbound attack vector for every project on Vercel"; patched Node.js versions rolling out to managed runtimes; WAF "does not replace patching". |

## 2. Linux distributions

| Distribution | Status |
|---|---|
| **Debian** | [Tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497): **13 trixie** `1.1.0-2+deb13u1` ([DSA-6582-1](https://security-tracker.debian.org/tracker/DSA-6582-1)); **12 bookworm** `1.0.9-2+deb12u1` ([DLA-4855-1](https://security-tracker.debian.org/tracker/DLA-4855-1)). Note: "nodejs and python-brotlicffi use system provided brotli library", so the brotli update covers them. Freexian ELTS ([tracker](https://deb.freexian.com/extended-lts/tracker/CVE-2026-111497)): **11 bullseye** `1.0.9-2+deb11u1`, **10 buster** `1.0.7-2+deb10u2` (ELA-1861-1); stretch end-of-life, unfixed. |
| **Ubuntu** | [USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1) (26 Oct): 26.10 `1.2.0-4ubuntu0.1`, 26.04 LTS `1.2.0-3ubuntu0.1`, 24.04 LTS `1.1.0-2ubuntu0.1`, 22.04 LTS `1.0.9-2ubuntu0.1`. 20.04 / 18.04 / 16.04 brotli: "Needs evaluation". nodejs "Not affected" on 22.04 and later (system brotli) and on 18.04 and earlier; **20.04 nodejs: Vulnerable** (vendored brotli). |
| **Red Hat Enterprise Linux** | Important, CVSS 3.1 8.1. **brotli fixed** (26 Oct): EL8 `brotli-1.0.6-5.el8_10` (RHSA-2026:90501), EL9 `brotli-1.0.9-10.el9_8.1` (RHSA-2026:90495), EL10 `brotli-1.1.0-8.el10_2.1` (RHSA-2026:90449); EUS / AUS / E4S streams on 27 Oct (RHSA-2026:90888 to :90893, :90914). **Affected, no fix yet** (bundled copy): EL8 `nodejs:24`, EL9 `nodejs:24` and `nodejs:26`, **.NET 8.0 on EL8 / 9 / 10**. Not affected (system brotli; update brotli): `nodejs:22` on EL8 / 9, Node.js 22 / 24 / 26 on EL10, .NET 9 / 10 / 11. Also affected: JBCS httpd brotli, AAP, Satellite, RHCOS (OCP 4), Service Mesh istio-proxy, Keycloak. Firefox / Thunderbird 140.10 are listed as fixed. [RHSB-2026-015](https://access.redhat.com/security/vulnerabilities/RHSB-2026-015) status "Ongoing". Source: [CSAF VEX](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-111497.json). |
| **AlmaLinux** | Same NVRs as RHEL: [ALSA-2026:90501](https://errata.almalinux.org/8/ALSA-2026-90501.html) (EL8, 26 Oct), [ALSA-2026:90495](https://errata.almalinux.org/9/ALSA-2026-90495.html) (EL9, 27 Oct), [ALSA-2026:90449](https://errata.almalinux.org/10/ALSA-2026-90449.html) (EL10, 27 Oct). Node.js / .NET streams: follow RHEL. |
| **Rocky Linux** | No brotli advisory yet (Apollo errata API, newest entry 27 Oct 12:08 UTC). |
| **Oracle Linux** | [CVE page](https://linux.oracle.com/cve/CVE-2026-111497.html): brotli ELSA-2026-500512 / -90501 (OL8), ELSA-2026-500513 (OL9), ELSA-2026-500514 / -90449 (OL10). **Node.js also fixed** (26 Oct): OL8 ELSA-2026-500519 / -500520, OL9 ELSA-2026-500517 / -500518, OL10 nodejs22 ELSA-2026-500516, nodejs24 ELSA-2026-500515. |
| **Amazon Linux** | [ALAS](https://explore.alas.aws.amazon.com/CVE-2026-111497.html): AL2023 brotli ALAS2023-2026-3334 and nodejs24 ALAS2023-2026-3330 (24 Oct); AL2027 Preview brotli ALAS2027-2026-244, nodejs24 ALAS2027-2026-245. AL2023 `nodejs` and `nodejs20`: "No Fix Planned"; nodejs22: not affected. |
| **SUSE** | [CVE page](https://www.suse.com/security/cve/CVE-2026-111497.html), overall "Pending", no SUSE-SU yet. **In QA:** libbrotli `1.0.7-150200.3.8.1` (SLES / SAP 15 SP4–SP7, SLE Micro 5.4 / 5.5); nodejs22 `22.23.4` (15 SP6 / SP7), nodejs24 `24.22.1` (15 SP7). **In progress:** SLES / SAP 16.0 / 16.1, SUSE Linux Micro 6.0–6.2 (brotli; nodejs22 / nodejs24 on 16.x). Affected without fix: openSUSE Leap 16.0, SLE Micro 5.3. Liberty Linux 8 / 9 / 10: released via the RHSAs above. |
| **Remi repository** | Ships no Brotli library or Node.js. `php-brotli` 0.21.1-1 (25 Oct) builds against the system library: the spec has `%bcond_without libbrotli`, `BuildRequires: brotli-devel` and removes the bundled copy (`rm -r brotli`). The OS brotli update is the fix. |

## 3. Upstream components (bundled copies)

| Component | Fixed in |
|---|---|
| Google Brotli | `1.2.1`, `1.1.1`, `1.0.10` ([releases](https://github.com/google/brotli/releases), 21 Oct) |
| Node.js | `26.12.1`, `24.22.1`, `22.23.4` ([blog](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)); EOL lines: no fix |
| Python | Brotli `1.2.1`, brotlicffi `1.2.1.0` ([GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35), PYSEC-2026-4322 / -4323) |
| .NET | `8.0.33`, `9.0.22`, `10.0.14`, `11.0.0-rc.3` ([dotnet/announcements#494](https://github.com/dotnet/announcements/issues/494), 25 Oct); ".NET Framework is not affected" |
| Envoy / Istio | Envoy `1.40.0`, `1.39.3`, `1.38.6`, `1.37.8`, `1.36.12` ([GHSA-3wvj-j6qm-62mr](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr)); Istio `1.31.2`, `1.30.6`, `1.29.9` ([ISTIO-SECURITY-2026-007](https://istio.io/latest/news/security/istio-security-2026-007/)); only with Brotli decompression enabled |
| PHP | Windows builds `8.5.12-1`, `8.4.27-1`, `8.3.36-1`, `8.2.35-1` bundle Brotli 1.2.1 ([php.net](https://www.php.net/archive/2026.php), 26 Oct; reachable via cURL automatic decompression); PECL brotli `0.21.1` ([release](https://github.com/kjdev/php-ext-brotli/releases)) |
| Others | Ruby brotli gem `0.9.1` ([issue #64](https://github.com/miyucy/brotli/issues/64)); Brotli4j `1.24.0`; Go andybalholm/brotli `1.2.7` (port of the fix); Bun `1.4.4` (release notes list Brotli among security fixes, no CVE ID) |

## 4. How to check

- **System library:** `rpm -q --changelog brotli | grep CVE-2026-111497` or the Debian / Ubuntu changelog; backports keep the old upstream version number.
- **Node.js:** check `node --version` against the fixed releases. Do **not** rely on `process.versions.brotli`: ELLIO reports that "process.versions.brotli reports 1.2.0 on a patched build and on a vulnerable one" (the v24.22.1 source tree confirms it).
- **Python:** `pip show Brotli brotlicffi` (wheels bundle the decoder).
- **.NET:** `dotnet --list-runtimes`.
- **After updating:** restart processes that loaded the old library (`needs-restarting -s`, `checkrestart`); rebuild and redeploy container images.

## Known gaps

- **Not checked:** Akamai research blog (403), Citrix support search, Check Point support KB search; Sophos only via RSS.
- **Pending vendor statements:** Cisco (interim), Fortinet (47 under investigation), F5 (all products "**"), Rocky Linux, SUSE.
- **Not verified (secondary only):** the [broccoli2shell.com](https://broccoli2shell.com/) tracker lists more bundled copies not fixed as of 27 Oct (DuckDB, Apache Arrow, 7-Zip-zstd, p7zip, EDK II, v8-jsi, woff2). Use it as a lead, not as proof.
- **Not covered yet:** other enterprise vendors (Microsoft products beyond .NET, VMware / Broadcom, HPE, NetApp, Splunk, Trend Micro, Kaseya and others from the PHP2Shell sweep).
