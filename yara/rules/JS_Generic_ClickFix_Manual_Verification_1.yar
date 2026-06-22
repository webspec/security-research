/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule JS_Generic_ClickFix_Manual_Verification_1
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
        yarahub_reference_md5 = "7fa6385ceb0beb80762370f92cd070c3"

        description = "Detects fake Cloudflare manual verification pages that instruct the user to open Run or Terminal and paste a command"

        family = "clickfix"
        confidence = "high"
        fp_risk = "low"

    strings:
        $cf_1 = "<title>Just a moment...</title>" ascii nocase
        $cf_2 = "Ray ID:" ascii nocase
        $cf_3 = "Cloudflare" ascii nocase
        $cf_4 = "Performance &amp; security" ascii nocase
        $cf_5 = "needs to review the security of your connection before proceeding" ascii nocase

        $verify_1 = "verify-window" ascii nocase
        $verify_2 = "Verification Steps" ascii nocase
        $verify_3 = "Perform the steps above to finish verification" ascii nocase
        $verify_4 = "I am not a robot" ascii nocase
        $verify_5 = "not a robot" ascii nocase
        $verify_6 = "id=\"verifying\"" ascii nocase
        $verify_7 = "cb-container" ascii nocase

        $win_1 = "Press <strong>Win</strong>" ascii nocase
        $win_2 = "fa-windows" ascii nocase
        $win_3 = "Then press <strong>Ctrl</strong>" ascii nocase
        $win_4 = "Press <strong>Enter</strong>" ascii nocase
        $win_5 = "fa-regular fa-keyboard" ascii nocase

        $mac_1 = "command Key" ascii nocase
        $mac_2 = "<b>⌘</b> + <b>SPACE</b>" ascii
        $mac_3 = "open spotlight" ascii nocase
        $mac_4 = "Type <b>Terminal</b>" ascii nocase
        $mac_5 = "command into Terminal" ascii nocase
        $mac_6 = "<b>⌘</b> + <b>V</b>" ascii

    condition:
        filesize < 3MB and
        (
            (
                4 of ($cf_*) and
                1 of ($verify_*) and
                4 of ($win_*)
            )
            or
            (
                4 of ($cf_*) and
                2 of ($verify_*) and
                4 of ($mac_*)
            )
        )
}
