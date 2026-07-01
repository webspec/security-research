/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule Generic_ClickFix_Command_Stager_1
{
    meta:
        author = "Caileb Murphy"
        company = "Webspec"
        company_site = "https://www.webspec.com/"

        copyright = "Copyright 2026 Webspec Design, LLC"
        license = "CC BY 4.0"
        yarahub_license = "CC BY 4.0"
        license_url = "https://creativecommons.org/licenses/by/4.0/"
        date = "2026-06-17"
        tlp = "clear"
        yarahub_rule_matching_tlp = "clear"
        yarahub_rule_sharing_tlp = "clear"
        yarahub_uuid = "f0cff656-b725-4f57-8b63-6ed9fea18edf"
        yarahub_reference_md5 = "5b8be20e147d7e943bd138da91da7f7f"

        description = "Detects command stagers and injected script loaders associated with ClickFix payload delivery"

        family = "clickfix"
        confidence = "high"
        fp_risk = "low"

    strings:
        /* Network probes seen before the payload branch runs. */
        $ps_probe_1 = "$progressPreference = 'SilentlyContinue'" ascii nocase
        $ps_probe_2 = "https://api.github.com/zen" ascii
        $ps_probe_3 = "https://httpbin.org/get" ascii
        $ps_probe_4 = "https://ifconfig.me/ip" ascii
        $ps_probe_5 = "https://www.cloudflare.com/cdn-cgi/trace" ascii
        $ps_probe_6 = "Start-Sleep -Milliseconds (Get-Random" ascii nocase
        $ps_probe_7 = "Invoke-WebRequest -Uri" ascii nocase
        $ps_probe_8 = "-UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue" ascii nocase

        /* Obfuscated ActiveX launcher fragments from the same command chain. */
        $activex_1 = "ActiveXObject" ascii
        $activex_2 = "objShell" ascii
        $activex_3 = "function _0x" ascii
        $activex_4 = "while(!![])" ascii
        $activex_5 = "parseInt(_0x" ascii
        $activex_cmd_1 = "power" ascii
        $activex_cmd_2 = "shell" ascii
        $activex_cmd_3 = "\\x20-Win" ascii
        $activex_cmd_4 = "dowSt" ascii
        $activex_cmd_5 = "idden" ascii
        $activex_cmd_6 = ".WebC" ascii
        $activex_cmd_7 = "loadS" ascii
        $activex_cmd_8 = "tp://" ascii

        /* Injected JavaScript that pulls script text through a local endpoint. */
        $xhr_1 = "new XMLHttpRequest()" ascii
        $xhr_2 = ".open('POST'," ascii
        $xhr_3 = ".setRequestHeader('Content-Type','application/json')" ascii
        $xhr_4 = ".responseType='text'" ascii
        $xhr_5 = ".onload=function()" ascii
        $xhr_6 = ".status===200" ascii
        $xhr_7 = "document.createElement('script')" ascii
        $xhr_8 = ".textContent=" ascii
        $xhr_9 = ".responseText" ascii
        $xhr_10 = "document.head.appendChild" ascii
        $xhr_11 = ".send(JSON.stringify(" ascii
        $xhr_12 = "wp-json/" ascii
        $xhr_13 = "wp-admin/admin-ajax.php" ascii

    condition:
        filesize < 3MB and
        (
            (
                /* Probe-heavy PowerShell stager. */
                7 of ($ps_probe_*)
            )
            or
            (
                /* Split ActiveX command builder. */
                all of ($activex_*) and
                5 of ($activex_cmd_*)
            )
            or
            (
                /* XHR loader that writes returned script into the page. */
                9 of ($xhr_*) and
                1 of ($xhr_12, $xhr_13)
            )
        )
}
