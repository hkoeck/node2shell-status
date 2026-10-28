# Node2Shell / Broccoli2Shell / HTTP2Shell (CVE-2026-111497) – Enterprise Vendor and Distribution Status

> [!WARNING]
> **AI-generated content.** This document was researched and written by an AI assistant (Claude, Anthropic). Statements were checked against the raw text of the linked primary source (HTML/JSON/CSAF, not summaries) **except where marked as not verified**; provenance is logged in [VERIFICATION.md](VERIFICATION.md). It may still contain errors and goes stale quickly. **Always verify against the vendor source before acting.** No warranty.

**Status:** 28 October 2026, 10:30 UTC (update 2). New in this update: 127 URLs fetched with curl (09:56–10:19 UTC), about 40 portal pages read in a browser (09:58–10:18 UTC), plus BSI / CERT-FR (10:21 UTC). Re-read 10:20–10:30 UTC: all 67 update-1 curl sources, the Rocky Apollo API, Sophos RSS, the SonicWall API and both F5 articles. Only wording or secondary-source changes were found. Not re-read in update 2: the Juniper and Ivanti portal searches (09:42–09:46 UTC). Could not check (bot protection, login, or the page did not render): Akamai, Broadcom / VMware portal, NetApp advisory list, Sophos advisory page (RSS read instead), Zscaler, Kaseya, Arista, Extreme, Infoblox, Forcepoint, Trellix, Netskope, Gigamon, the Check Point support KB search, community.citrix.com. Per-source times: [VERIFICATION.md](VERIFICATION.md). Change history: [CHANGELOG.md](CHANGELOG.md).

## Key facts

- **The bug:** out-of-bounds write in the Google Brotli C decoder (`c/dec/decode.c`), CWE-787 / CWE-252. Node.js: "An invalid block switch was reported as a temporary need for more input instead of a permanent format error, so the streaming decoder kept appending input bytes to an eight-byte internal buffer." Impact: crash, memory disclosure or remote code execution in any process that decompresses attacker-controlled Brotli data.
- **Affected / fixed:** Brotli 1.0.3 up to 1.2.0; fixed in **1.0.10, 1.1.1, 1.2.1** (21 Oct 2026). The upstream fix commit [0ed4268](https://github.com/google/brotli/commit/0ed4268) is dated 27 Feb 2026. Node.js is fixed in **22.23.4, 24.22.1, 26.12.1** (21 Oct); end-of-life lines get no fix.
- **Severity:** CNA (Google) CVSS 4.0 **9.2 Critical**. Node.js: "high". Microsoft: **Critical** for .NET / Visual Studio (CVSS 8.1). Red Hat, Oracle, Amazon: Important, CVSS 3.1 8.1 (AC:H). SUSE: CVSS 3.1 8.1. Ubuntu: priority Medium. BSI: "hoch".
- **Exploitation:**
  - **CISA KEV:** added 27 Oct 2026 "based on evidence of active exploitation", due **10 Nov 2026** (BOD 26-04), forensic triage "No". CISA SSVC (ADP) in the CVE record: Exploitation `active` (23 Oct).
  - **In the wild:** [ELLIO](https://ellio.tech/en/blog/node2shell-cve-2026-111497-rce-on-stock-nodejs-builds/) (update 26 Oct): "ELLIO sensors have recorded CVE-2026-111497 exploit traffic in the wild, carrying the public exploit that we confirmed gets a shell on vulnerable builds." Tenable: "Tenable has not independently confirmed this activity." A second honeypot hit (Previdian, 27 Oct) is reported only by The Hacker News (**not verified**).
  - **Shells on stock builds:** [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/) ran code on the official Node.js 24.22.0 Linux arm64 image via `fetch()` and Express / body-parser request bodies ("execution took multiple attempts in our setup"). ELLIO reproduced this on x86-64 against four targets.
  - **Public PoCs:** on GitHub (confirmed by Cisco PSIRT and Tenable). BSI noted on 27 Oct: "Exploit aufgenommen".
  - **Vendors not aware of malicious use:** Microsoft (exploited "No"), Palo Alto, Cisco, Fortinet (Known Exploited: `No`).
  - **Contradicting vendor text:** Red Hat still writes "there is no public, reliable remote code execution proof-of-concept".
- **Exposure paths:**
  - Node.js `zlib` Brotli APIs and `fetch()`. `fetch()` decodes `br` responses, so a malicious server can attack the client.
  - Express 5.0.0–5.3.0 / body-parser 2.0.0–2.3.0 request parsers (Imperva tested these).
  - The Next.js image optimizer `/_next/image` (F5, Cloudflare).
  - Python urllib3 / requests / aiohttp / httpx, when Brotli or brotlicffi is installed.
  - .NET: only with Brotli decompression enabled.
  - Envoy / Istio: only with the Brotli decompressor.
  - libcurl with automatic decompression.
  - Vercel: "Node.js does not decode Brotli data on its own."
- **System library vs. bundled copy:**
  - **Linked to the system `libbrotli`:** many distribution packages, for example Debian, Ubuntu ≥ 22.04, RHEL `nodejs:22` and the EL10 Node.js packages, and .NET 9+ on RHEL. The distribution's brotli update fixes these.
  - **Own copy, needs its own update:** upstream Node.js binaries, the official Docker images, CloudLinux `alt-nodejs`, Python wheels, .NET 8 and many appliances. CloudLinux: "Updating the system brotli package does not help, because alt-nodejs packages carry their own copy of Brotli."
  - **In both cases:** running processes keep the old decoder until they are restarted.

## 1. Network and security appliances

| Vendor | Status |
|---|---|
| **Palo Alto Networks** | [Advisory](https://security.paloaltonetworks.com/CVE-2026-111497) (upd. 28 Oct), CVSS 4.0 9.2, urgency moderate. PAN-OS 11.2 / 12.1 / 12.2 on PA- and VM-Series are affected only with Brotli inspection **and** TLS decryption enabled. Brotli encoding is off by default from 11.2.4. The management web UI / API is not affected. **Released:** `12.2.4-h1`, `12.1.7-h11`, `11.2.16-h1`, `11.2.13-h4`, `11.2.10-h17`, `11.2.7-h23`. **Due:** `12.1.4-h13` (ETA 10/29), `12.1.10-h3` and `11.2.4-h23` (ETA 10/30). `11.2.10-h16` "only includes the fix for PHP vulnerabilities". Workaround: `set system setting brotli-encoding disable` (check: `show system setting brotli`). Not affected: PAN-OS 11.1 / 10.2, Panorama, Idira self-hosted. Prisma Cloud AppSec Transporter Client: fixed in `0.2.9`. SaaS (ADEM, CIE, Prisma AIRS Gateway and others): remediated by PAN. |
| **Cisco** | [cisco-sa-oct2026-node-js-Jj3SQ19u](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-oct2026-node-js-Jj3SQ19u) v1.0 **Interim** (27 Oct 21:30 GMT). It also covers Node.js CVE-2026-105482 / -105483 / -106069. The vulnerable and not-vulnerable lists are still empty. Priority products under investigation: ISE, Catalyst SD-WAN Manager, IOS, IOS XE, IOS XR, NX-OS, ASA, FMC, FTD. Also under investigation: 90 more products and services (selection: Catalyst Center, Nexus Dashboard / NDFC, Secure Network Analytics, Secure Workload, ThousandEyes, Umbrella, Webex, Intersight, AppDynamics; full list: advisory). "If a product is not listed within this advisory, Cisco's review indicates that the product is not affected by this vulnerability." No workarounds. |
| **Fortinet** | [FG-IR-26-187](https://fortiguard.fortinet.com/psirt/FG-IR-26-187) "Multiple Node.js CVEs" (upd. 27 Oct), component GUI. The advisory is rated Critical / CVSS 3 9.8; this CVE itself is listed as "high". No virtual patch, no fixed versions yet. Under investigation (47; selection): FortiOS, FortiProxy, FortiMail, FortiNAC / -F, FortiSIEM, FortiSandbox, FortiSwitch, FortiEDR, FortiSASE, FortiGate Cloud. Not impacted (22; selection): FortiManager, FortiAnalyzer, FortiClient EMS, FortiAuthenticator, FortiWeb, FortiSOAR. FortiADC, FortiDeceptor and FortiPresence appear in **both** lists. Full lists: advisory. |
| **F5** | [K000163902](https://my.f5.com/manage/s/article/K000163902) (upd. 28 Oct). Still researching ("**"): BIG-IP 17.x / 21.x, BIG-IQ, BIG-IP Next, F5OS, Distributed Cloud, NGINX One Console, AI Gateway. **NGINX Plus and NGINX Open Source: not vulnerable.** `nginx-plus-module-brotli` uses the OS library ("No NGINX Plus Brotli module update is required"); update the OS package instead. Mitigations: a custom Advanced WAF signature that blocks `Content-Encoding: br` on POST / PUT / PATCH, and a `/_next/image` URL restriction for Next.js. Other Node.js CVEs: [K000163874](https://my.f5.com/manage/s/article/K000163874). |
| **HPE / Aruba** | [Critical vulnerability alert](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00001284en_us&page=GUID-492AC266-D967-46CA-BD3A-75D57CBD0B32.html&docLocale=en_US) (27 Oct), no products named: "Should any vulnerable products be discovered, HPE security bulletins will be issued when fixes become available." |
| **Trend Micro** | [KA-0024830](https://success.trendmicro.com/en-US/solution/KA-0024830) (upd. 27 Oct). Own products are under "urgent assessment"; "More information will be updated if any products are impacted". Protection: TippingPoint filter **48101** and Vision One detections (section 2). |
| **Check Point** | No product statement found. IPS protection [CPAI-2026-15802](https://advisories.checkpoint.com/defense/advisories/public/2026/cpai-2026-15802.html) (24 Oct, Critical) for Security Gateway R82 / R81 / R80 / R77 / R75. The support KB search could not be checked. |
| **Citrix / NetScaler** | Checked, nothing found in Citrix's support search. It searches the KB, security bulletins, community and blog together. Searches for the CVE ID, "brotli" and "Node.js" return no item that mentions the CVE. The newest security bulletin is still the PHP2Shell advisory (27 Oct). Citrix now also publishes CVE disclosures on community.citrix.com, which could not be read (Cloudflare challenge). |
| **Checked, nothing found** | **Sophos** (advisory RSS), **SonicWall** (PSIRT API, newest entry 14 Oct), **Juniper** (support portal search only; it can miss reference advisories), **Ivanti** (hub search: only customer questions about EPMM / Sentry and vADC, no Ivanti answer), **WatchGuard** (PSIRT, newest 27 Oct), **Barracuda** (trust center), **Nutanix** (advisories, newest #0059 of 27 Oct), **Splunk** (advisories, newest 22 Oct), **A10** (advisories), **Siemens** (ProductCERT CSAF feed, newest 27 Oct), **SolarWinds** (advisories), **Oracle** (security alerts, newest 26 Oct), **Elastic** (security announcements, newest 6 Oct; one unanswered customer question about Elasticsearch, 24 Oct). |
| **Could not check** | Broadcom / VMware: the portal renders no list. A news report of an SDDC Manager advisory for this CVE is **not verified**. NetApp: the list did not render. Akamai: HTTP 403. Zscaler: the trust portal returns 404, and the research blog list does not show its PHP2Shell post either, so it cannot be used. Kaseya: the page shell has no advisory list. Arista, Extreme, Infoblox, Forcepoint, Trellix, Netskope, Gigamon: bot protection, error pages or login. |

## 2. WAF, IPS and detection content

| Vendor | Content | Notes |
|---|---|---|
| Cloudflare | Emergency release ([changelog](https://developers.cloudflare.com/changelog/post/2026-10-25-emergency-waf-release/), 25 Oct) adds two Managed Ruleset rules: "Brotli - Request Content-Encoding - CVE:CVE-2026-111497" and a Next.js rule for `/_next/image` | "enabled by default with their action set to Log". Cloudflare warns that blocking the Next.js rule "may prevent optimized images from loading" |
| Fastly Next-Gen WAF | "Added virtual patch for CVE-2026-111497 (Node2Shell, HTTP2Shell)" ([changelog](https://www.fastly.com/documentation/reference/changes/), 26 Oct) | – |
| Imperva | "Imperva has added WAF rules for CVE-2026-111497." ([blog](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)) | – |
| Vercel | WAF rules deployed "the same day that block the inbound attack vector for every project on Vercel" ([bulletin](https://vercel.com/kb/bulletin/node-js-security-advisory)) | "does not replace patching" |
| F5 Advanced WAF | Custom attack signature (rule text in K000163902) | Blocks all `Content-Encoding: br` POST / PUT / PATCH |
| Check Point | IPS **CPAI-2026-15802**, log "Web Server Enforcement Violation" | – |
| Trend Micro | TippingPoint filter **48101** "HTTP: Google Brotli Decoder Out-of-Bounds Write Vulnerability"; Vision One detections for Node.js child processes and outbound connections | – |
| **Scanners** | **Tenable:** 63 plugins ([list](https://www.tenable.com/cve/CVE-2026-111497/plugins)), e.g. 372406 / 372407 (Python Brotli / brotlicffi), 372462–372464 (.NET Core, SDK, ASP.NET Core OOB), plus distribution local checks. **Qualys** ([blog](https://blog.qualys.com/product-tech/2026/10/23/node-js-patches-brotli-remote-code-execution-flaw-find-vulnerable-runtimes-before-attackers-do)): QID **389117** (Node.js on Windows / macOS). The TotalAppSec check QID **533085** is intrusive: "This intrusive check may cause applications or APIs running on vulnerable Node.js versions to crash" | WAF rules cover inbound request bodies only. Fetched responses and file input need the runtime or library update |

## 3. Linux distributions and repositories

| Distribution | Status |
|---|---|
| **Debian** | [Tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497): **13 trixie** `1.1.0-2+deb13u1` ([DSA-6582-1](https://security-tracker.debian.org/tracker/DSA-6582-1)); **12 bookworm** `1.0.9-2+deb12u1` ([DLA-4855-1](https://security-tracker.debian.org/tracker/DLA-4855-1)). Tracker note: "nodejs and python-brotlicffi use system provided brotli library" (urgency "unimportant"). Freexian ELTS ([tracker](https://deb.freexian.com/extended-lts/tracker/CVE-2026-111497)): **11 bullseye** `1.0.9-2+deb11u1`, **10 buster** `1.0.7-2+deb10u2` (ELA-1861-1). |
| **Ubuntu** | [USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1) (26 Oct): 26.10 `1.2.0-4ubuntu0.1`, 26.04 LTS `1.2.0-3ubuntu0.1`, 24.04 LTS `1.1.0-2ubuntu0.1`, 22.04 LTS `1.0.9-2ubuntu0.1`. brotli on 20.04 / 18.04 / 16.04: "Needs evaluation". nodejs: "Not affected" on 22.04 and later (system brotli); **Vulnerable on 20.04** (vendored brotli). |
| **Red Hat Enterprise Linux** | Important, CVSS 3.1 8.1 ([CSAF VEX](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-111497.json)). **brotli fixed** (26 Oct): EL8 `brotli-1.0.6-5.el8_10` (RHSA-2026:90501), EL9 `brotli-1.0.9-10.el9_8.1` (RHSA-2026:90495), EL10 `brotli-1.1.0-8.el10_2.1` (RHSA-2026:90449). EUS / AUS / E4S on 27 Oct (RHSA-2026:90888 to :90893, :90914). **Affected, no fix yet** (bundled copy): EL8 `nodejs:24`, EL9 `nodejs:24` / `nodejs:26`, **.NET 8.0 on EL8 / 9 / 10**. Not affected (system brotli; update brotli): `nodejs:22` on EL8 / 9, Node.js on EL10, .NET 9 / 10 / 11. Also affected: JBCS httpd brotli, AAP, Satellite, RHCOS (OCP 4), Service Mesh istio-proxy, Keycloak. [RHSB-2026-015](https://access.redhat.com/security/vulnerabilities/RHSB-2026-015): "Ongoing". |
| **AlmaLinux** | Same NVRs as RHEL: [ALSA-2026:90501](https://errata.almalinux.org/8/ALSA-2026-90501.html) (EL8, 26 Oct), [ALSA-2026:90495](https://errata.almalinux.org/9/ALSA-2026-90495.html) (EL9, 27 Oct), [ALSA-2026:90449](https://errata.almalinux.org/10/ALSA-2026-90449.html) (EL10, 27 Oct). |
| **Rocky Linux** | Community: no brotli advisory yet (Apollo errata API, newest entry 27 Oct 12:08 UTC). CIQ Rocky Linux 9.2 LTS: Tenable plugin 372455 cites `ciqsa-2026_1720` (**not verified** at CIQ). |
| **Oracle Linux** | [CVE page](https://linux.oracle.com/cve/CVE-2026-111497.html). brotli: ELSA-2026-500512 / -90501 (OL8), -500513 (OL9), -500514 / -90449 (OL10). **Node.js** (26 Oct): OL8 ELSA-2026-500519 / -500520, OL9 -500517 / -500518, OL10 nodejs22 -500516, nodejs24 -500515. |
| **Amazon Linux** | [ALAS](https://explore.alas.aws.amazon.com/CVE-2026-111497.html): AL2023 brotli ALAS2023-2026-3334 and nodejs24 ALAS2023-2026-3330 (24 Oct); AL2027 Preview ALAS2027-2026-244 / -245. AL2023 `nodejs` and `nodejs20`: "No Fix Planned". AL2023 nodejs22: not affected. |
| **SUSE** | [CVE page](https://www.suse.com/security/cve/CVE-2026-111497.html): overall "Pending", no SUSE-SU yet. **In QA:** libbrotli `1.0.7-150200.3.8.1` (SLES / SAP 15 SP4–SP7, SLE Micro 5.4 / 5.5); nodejs22 `22.23.4` (15 SP6 / SP7); nodejs24 `24.22.1` (15 SP7). **In progress:** brotli on SLES / SAP 16.0 / 16.1 and SUSE Linux Micro 6.0–6.2; nodejs22 / nodejs24 on 16.x. Affected without fix: openSUSE Leap 16.0, SLE Micro 5.3. Liberty Linux 8 / 9 / 10: fixed via the RHSAs. |
| **Azure Linux 3.0** | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497): brotli fixed in `1.2.1-1`, nodejs in `24.22.1-1`. |
| **Photon OS 5** | nodejs `24.19.0-5.ph5` "Fixed" ([CVE metadata](https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon5.0.json)). |
| **Alpine 3.22** | `brotli-libs` `1.1.1-r0` (built 22 Oct). |
| **CloudLinux / TuxCare** | [Blog](https://blog.cloudlinux.com/node-js-october-2026-security-releases) (last updated 22 Oct 16:54 UTC): `alt-nodejs` 12–26 and `ea-nodejs22` bundle their own Brotli. As of 22 Oct 16:54 UTC, fixed packages were out for all lines except alt-nodejs22 on CloudLinux 7 and the standard EA4 `ea-nodejs22`: "31 of 33 CloudLinux builds and 76 of 99 TuxCare builds are released". |
| **Remi repository** | Ships no Brotli library or Node.js. `php-brotli` 0.21.1-1 (25 Oct) builds against the system library: the spec has `%bcond_without libbrotli` and `BuildRequires: brotli-devel` and removes the bundled copy. The OS brotli update is the fix. |

## 4. Cloud platforms and container images

| Platform | Status |
|---|---|
| **Microsoft Azure** | App Service / Functions ([blog](https://azure.github.io/AppService/2026/10/26/), 26 Oct) are rolling out updated built-in **.NET** images. App Service for Linux: "complete on the Latest Platform Release Channel". App Service for Windows: "active through Safe Deployment Practices". Linux Functions: "in progress". No statement on Node.js runtimes found. |
| **AWS** | No bulletin for this CVE in the security bulletins list or RSS. Amazon Linux: section 3. |
| **Google Cloud** | No bulletin for this CVE in the security bulletins list. |
| **Vercel** | WAF rules on disclosure day; patched Node.js is rolling out to the managed runtimes ([bulletin](https://vercel.com/kb/bulletin/node-js-security-advisory)). |
| **Docker Official Image `node`** | Tags `24.22.1-*` and `22.23.4-*` are published; for example, `24.22.1-bookworm-slim` was updated 28 Oct 05:40 UTC. Rebuild images built on older tags. |
| **Red Hat images** | Hardened Images: brotli `1.2.1` (RHSA-2026:87420, 21 Oct). The VEX lists OpenShift Dev Spaces, RHOAI and Keycloak images as affected. |

## 5. Upstream components (bundled copies)

| Component | Fixed in |
|---|---|
| Google Brotli | `1.2.1`, `1.1.1`, `1.0.10` ([releases](https://github.com/google/brotli/releases), 21 Oct) |
| Node.js | `26.12.1`, `24.22.1`, `22.23.4` ([blog](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)); EOL lines: no fix |
| Microsoft .NET | `8.0.33`, `9.0.22`, `10.0.14` (SDK `8.0.427`, `9.0.320`, `10.0.403`) and `11.0.0-rc.3`, all 25 Oct ([dotnet/announcements#494](https://github.com/dotnet/announcements/issues/494), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497)). ".NET Framework is not affected" |
| Visual Studio, PowerShell | VS 2019 `16.11.61`, VS 2022 `17.14.43`, VS 2026 `18.11.2`; PowerShell `7.4.22`, `7.5.13`, `7.6.9` (MSRC: Important) |
| Python | Brotli `1.2.1`, brotlicffi `1.2.1.0` ([GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35), PYSEC-2026-4322 / -4323) |
| Envoy / Istio | Envoy `1.40.0`, `1.39.3`, `1.38.6`, `1.37.8`, `1.36.12` ([GHSA-3wvj-j6qm-62mr](https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr)); Istio `1.31.2`, `1.30.6`, `1.29.9` ([ISTIO-SECURITY-2026-007](https://istio.io/latest/news/security/istio-security-2026-007/)). Only affected with Brotli decompression enabled |
| PHP | Windows builds `8.5.12-1`, `8.4.27-1`, `8.3.36-1`, `8.2.35-1` bundle Brotli 1.2.1 ([php.net](https://www.php.net/archive/2026.php), 26 Oct); reachable via cURL automatic decompression. PECL brotli `0.21.1` |
| Others | Ruby brotli gem `0.9.1`; Brotli4j `1.24.0`; Go andybalholm/brotli `1.2.7` (a port of the fix); Bun `1.4.4` (its release notes list Brotli among the security fixes, without a CVE ID) |
| No fix release found | Electron (no Brotli mention in the last 40 release notes), Deno, Next.js (no advisory; F5 and Cloudflare cover `/_next/image`). curl / libcurl publish no advisory of their own; they use the system libbrotli |

## 6. Government / CERT advisories

- **CISA:** [KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/27/cisa-adds-two-known-exploited-vulnerabilities-catalog) (27 Oct), due date 10 Nov.
- **BSI (DE):** WID-SEC-2026-4117 "Node.js: Mehrere Schwachstellen", **hoch**, version 5 (27 Oct): "Exploit aufgenommen CVE-2026-111497" ([CSAF](https://wid.cert-bund.de/.well-known/csaf/white/2026/wid-sec-w-2026-4117.json)).
- **CSA Singapore:** [AL-2026-154](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-154/) "Critical Vulnerability in Node.js" (23 Oct): "Patch immediately."
- **CERT-FR:** [CERTFR-2026-AVI-1367](https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1367/) "Multiples vulnérabilités dans Node" (22 Oct); its CVE list was not readable.
- **Checked, nothing found:** CERT-EU advisories, Canada CCCS (RSS), NCSC-UK (RSS).

## Known gaps

- **Could not check:** see the status line. Most important: Broadcom / VMware, NetApp, Akamai and Zscaler (all published statements for PHP2Shell), the Check Point KB and the Citrix community site.
- **Still under investigation:** Cisco (interim, 99 products), Fortinet (47), F5 (all except NGINX), HPE, Trend Micro, Red Hat (RHSB "Ongoing").
- **Affected, no fix yet:**
  - RHEL `nodejs:24` / `nodejs:26` and .NET 8
  - SUSE (all in QA or in progress)
  - Ubuntu 20.04 nodejs
  - Amazon Linux `nodejs` / `nodejs20` (no fix planned)
  - Rocky Linux community
  - PAN-OS hotfixes due 29–30 Oct
- **Not verified (secondary only):**
  - the Previdian honeypot report
  - a VMware SDDC Manager advisory
  - CIQ `ciqsa-2026_1720`
  - the [broccoli2shell.com](https://broccoli2shell.com/) list of unfixed bundled copies (DuckDB, Apache Arrow, 7-Zip-zstd, p7zip, EDK II, v8-jsi, woff2)

  Use these as leads, not as proof.
- **Out of scope:** desktop and developer software (Electron apps, IDEs, Git for Windows), which often bundles Node.js or Brotli.

Absence of a vendor statement does not mean a product is not affected.

## Checking whether you are patched

```sh
# System library (backports keep the old version number)
rpm -q --changelog brotli | grep CVE-2026-111497                      # RHEL / Alma / Rocky / Oracle / SUSE / Amazon
zgrep CVE-2026-111497 /usr/share/doc/libbrotli1/changelog.Debian.gz   # Debian / Ubuntu
# Node.js: compare with 22.23.4 / 24.22.1 / 26.12.1
node --version
# Python and .NET bundled copies
pip show Brotli brotlicffi
dotnet --list-runtimes
# Processes still using the old library after the update
needs-restarting -s                                                   # RHEL family
grep -l brotlidec /proc/*/maps 2>/dev/null
```

Do **not** rely on `process.versions.brotli`: ELLIO reports that "process.versions.brotli reports 1.2.0 on a patched build and on a vulnerable one", and the v24.22.1 source tree confirms it. Rebuild and redeploy container images: updating the host does not update a runtime inside an image.

## Fork it and keep it current with an AI

1. Fork: click **Fork** on GitHub, or `gh repo fork hkoeck/node2shell-status --clone`.
2. Open the fork in an AI coding assistant with shell and web access (e.g. Claude Code) and give it the prompt from [UPDATE_PROMPT.md](UPDATE_PROMPT.md).
3. Review the diff. Every changed claim needs a row in [VERIFICATION.md](VERIFICATION.md) with source, UTC time and a verbatim quote.
4. Commit, push, optionally open a pull request back here.

## Sources

Upstream: [Node.js](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [google/brotli](https://github.com/google/brotli/releases), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-111497), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-111497) ·
Exploitation: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [ELLIO](https://ellio.tech/en/blog/node2shell-cve-2026-111497-rce-on-stock-nodejs-builds/), [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/), [Tenable FAQ](https://www.tenable.com/blog/brotli2shell-frequently-asked-questions-for-google-brotli-decoder-cve-2026-111497) ·
Distros: [Debian](https://security-tracker.debian.org/tracker/CVE-2026-111497), [Ubuntu](https://ubuntu.com/security/CVE-2026-111497), [Red Hat](https://access.redhat.com/security/cve/cve-2026-111497), [SUSE](https://www.suse.com/security/cve/CVE-2026-111497.html), [Oracle](https://linux.oracle.com/cve/CVE-2026-111497.html), [Amazon](https://explore.alas.aws.amazon.com/CVE-2026-111497.html).
Vendor and platform links are in the tables above.
