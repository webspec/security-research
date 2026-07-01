/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule JS_Generic_ClickFix_Delivery_1
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
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "4c12b3e7-7956-4b36-b666-e66da18c34eb"
        yarahub_reference_md5 = "c99c2ec3ba112b6dc27a0433a890bc3d"

        description = "Detects ClickFix delivery wrappers, cloakers, and packed loaders used to stage fake verification pages or commands"

        family = "clickfix"
        confidence = "high"
        fp_risk = "low"

    strings:
        /* Browser and automation checks used by delivery wrappers. */
        $cloaker_1 = "navigator.webdriver" ascii
        $cloaker_2 = "HeadlessChrome" ascii
        $cloaker_3 = "OfflineAudioContext" ascii
        $cloaker_4 = "WEBGL_debug_renderer_info" ascii
        $cloaker_5 = "/api/check" ascii
        $cloaker_6 = "/api/userjs/" ascii
        $cloaker_7 = "new Function(code)" ascii

        /* Remote script handoff through session state or WordPress paths. */
        $remote_script_1 = "sessionStorage" ascii
        $remote_script_2 = "__sync_load" ascii
        $remote_script_3 = "createElement" ascii
        $remote_script_4 = "insertBefore" ascii
        $remote_script_5 = "?data=" ascii
        $remote_script_6 = "JSON.stringify" ascii
        $remote_script_7 = "atob(" ascii
        $remote_script_8 = "wp-blog-footer.php" ascii

        /* Google Apps Script delivery page markers. */
        $apps_script_1 = "script.google.com" ascii nocase
        $apps_script_2 = "googleusercontent.com" ascii nocase
        $apps_script_3 = "IFRAME_SANDBOX" ascii
        $apps_script_4 = "userHtml" ascii
        $apps_script_5 = "window.open" ascii
        $apps_script_6 = "page.link" ascii
        $apps_script_7 = "Verifying you are human" ascii nocase

        /* Archive download and launch flow. */
        $ps_1 = "Join-Path $env:TEMP" ascii nocase
        $ps_2 = "Invoke-WebRequest" ascii nocase
        $ps_3 = "Expand-Archive" ascii nocase
        $ps_4 = "ProcessStartInfo" ascii nocase
        $ps_5 = "Start-Sleep" ascii nocase

        /* Older packed document.write loader. */
        $old_obf_1 = "document.write(lO)" ascii
        $old_obf_2 = "eval(unescape" ascii
        $old_obf_3 = "String.fromCharCode(57, 98, 53, 99, 54, 101)" ascii
        $old_obf_4 = "y3hGY8N[0]" ascii
        $old_obf_5 = "zLP=location.protocol+'0FD'" ascii

        /* ActiveX path used by legacy Windows browser payloads. */
        $activex_1 = "ActiveXObject" ascii
        $activex_2 = "WScript.Shell" ascii
        $activex_3 = "decodeURIComponent" ascii
        $activex_4 = "charCodeAt" ascii
        $activex_5 = "function _0x" ascii
        $activex_6 = "String['fromCharCode']" ascii
        $activex_7 = "objShell" ascii

        /* Base64 plus XOR decode path. */
        $xor_loader_1 = "s=atob(s)" ascii
        $xor_loader_2 = "new Uint8Array(len)" ascii
        $xor_loader_3 = "charCodeAt(i)^k" ascii
        $xor_loader_4 = "TextDecoder(\"utf-8\")" ascii
        $xor_loader_5 = "decodeURIComponent(escape(tmp))" ascii
        $xor_loader_6 = "new Function(_0x" ascii

        /* PowerShell reflection loader and shortcut dropper traces. */
        $ps_reflect_1 = "New-Object System.Net.WebClient" ascii nocase
        $ps_reflect_2 = ".DownloadData(" ascii nocase
        $ps_reflect_3 = "[System.Reflection.Assembly]::Load" ascii nocase
        $ps_reflect_4 = ".EntryPoint" ascii nocase
        $ps_reflect_5 = ".Invoke($null, @())" ascii nocase
        $ps_reflect_6 = "Invoke-WebRequest -Uri" ascii nocase
        $ps_reflect_7 = "-OutFile" ascii nocase
        $ps_reflect_8 = "[InternetShortcut]" ascii nocase

        /* Packed Cloudflare-style lure page. */
        $packed_cf_1 = "document.write(decodeURIComponent(escape(atob('" ascii
        $packed_cf_2 = "PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KPHRpdGxlPkJsYWNrPC90aXRsZT4KPHNjcmlwdD4K" ascii
        $packed_cf_3 = "Q09QWWJhc2U2NFRleHQ" ascii

    condition:
        filesize < 3MB and
        (
            /* Each branch is a complete delivery pattern from one observed family. */
            5 of ($cloaker_*) or
            6 of ($remote_script_*) or
            6 of ($apps_script_*) or
            4 of ($ps_*) or
            4 of ($old_obf_*) or
            ($activex_1 and 3 of ($activex_2, $activex_3, $activex_4, $activex_5, $activex_6, $activex_7)) or
            5 of ($xor_loader_*) or
            5 of ($ps_reflect_*) or
            all of ($packed_cf_*)
        )
}
