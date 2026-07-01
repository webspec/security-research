/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule JS_Generic_ClickFix_Workflow_1
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
        yarahub_uuid = "343c49d6-48c9-487c-ba10-a8170aa509a8"
        yarahub_reference_md5 = "7f3b690b91071c703e3dae56e1622953"

        description = "Detects ClickFix pages that copy a Windows command and guide the user through Run, paste, and Enter steps"

        family = "clickfix"
        confidence = "high"
        fp_risk = "low"

    strings:
        $copy_clip_1 = "clipboard.writeText" ascii nocase
        $copy_clip_2 = "navigator.clipboard" ascii nocase
        $copy_exec_1 = "execCommand('copy')" ascii nocase
        $copy_exec_2 = "execCommand(\"copy\")" ascii nocase
        $copy_exec_3 = "execCommand(\"\\x63\\x6f\\x70\\x79\")" ascii nocase
        $copy_textarea_1 = "createElement('textarea')" ascii nocase
        $copy_textarea_2 = "createElement(\"textarea\")" ascii nocase
        $copy_textarea_3 = "createElement(\"\\x74\\x65\\x78\\x74\\x61\\x72\\x65\\x61\")" ascii nocase
        $copy_verify_php = "verify.php" ascii nocase

        $lure_1 = "Verification Steps" ascii nocase
        $lure_2 = "Verify You Are Human" ascii nocase
        $lure_3 = "Checking if you are human" ascii nocase
        $lure_4 = "not a robot" ascii nocase
        $lure_5 = "recaptcha" ascii nocase
        $lure_6 = "Cloudflare" ascii nocase
        $lure_7 = "Ray ID" ascii nocase
        $lure_8 = "One-Time Device Verification" ascii nocase
        $lure_9 = "Hardware Fingerprint" ascii nocase
        $lure_10 = "90-Day Access Token" ascii nocase
        $lure_11 = "Verifying you are human" ascii nocase

        $win_1 = "Windows Key" ascii nocase
        $win_2 = "Windows Button" ascii nocase
        $win_3 = "Hold Windows key" ascii nocase
        $win_4 = "Windows</kbd>" ascii nocase
        $win_5 = "Win</kbd>" ascii nocase
        $win_6 = "Win + R" ascii nocase
        $win_7 = "Windows" ascii nocase

        $paste_1 = "Ctrl + V" ascii nocase
        $paste_2 = "CTRL + V" ascii nocase
        $paste_3 = "Ctrl+V" ascii nocase
        $paste_4 = "Ctrl</span> + <span" ascii nocase
        $paste_5 = "Ctrl</b> + <b>V" ascii nocase
        $paste_6 = "Strg+V" ascii nocase
        $paste_7 = "paste verification code" ascii nocase
        $paste_8 = "paste the copied data" ascii nocase
        $paste_9 = "<b>Ctrl</b> + <b>V" ascii nocase
        $paste_10 = "Ctrl</kbd> + <kbd" ascii nocase

        $enter_1 = "Press Enter" ascii nocase
        $enter_2 = "Press <b>Enter</b>" ascii nocase
        $enter_3 = "Press <span" ascii nocase
        $enter_4 = "confirm with" ascii nocase
        $enter_5 = "verification window" ascii nocase
        $enter_6 = "<b>Enter</b>" ascii nocase
        $enter_7 = "Enter</kbd>" ascii nocase

        $payload_1 = "powershell" ascii nocase
        $payload_2 = "Invoke-WebRequest" ascii nocase
        $payload_3 = "Invoke-RestMethod" ascii nocase
        $payload_4 = "cmd.exe" ascii nocase
        $payload_5 = "mshta" ascii nocase
        $payload_6 = "DownloadString" ascii nocase
        $payload_7 = "ExecutionPolicy" ascii nocase
        $payload_8 = "pOwERsheLl" ascii
        $payload_9 = "C\"\\x4f\\x6d\"ManD" ascii
        $payload_10 = "cmd /c" ascii nocase
        $payload_11 = "Terminal/PowerShell" ascii nocase

        $brand_1 = "admin.booking.com" ascii nocase
        $brand_2 = "Booking.com" ascii nocase
        $brand_3 = "bui-" ascii nocase
        $brand_4 = "ext-header" ascii nocase
        $brand_5 = "keyboard-css" ascii nocase
        $brand_6 = "Google Docs" ascii nocase
        $brand_7 = "Run Dialog" ascii nocase

    condition:
        filesize < 3MB and
        (
            (
                (1 of ($copy_clip_*) or (1 of ($copy_exec_*) and 1 of ($copy_textarea_*))) and
                1 of ($lure_*) and
                1 of ($win_*) and
                1 of ($paste_*) and
                1 of ($enter_*) and
                (1 of ($payload_*) or 1 of ($brand_*))
            )
            or
            (
                $copy_verify_php and
                1 of ($copy_exec_*) and
                1 of ($copy_textarea_*)
            )
            or
            (
                1 of ($copy_clip_*) and
                1 of ($win_*) and
                1 of ($paste_*) and
                1 of ($enter_*) and
                $brand_5
            )
            or
            (
                (1 of ($copy_clip_*) or (1 of ($copy_exec_*) and 1 of ($copy_textarea_*))) and
                $brand_6 and
                $brand_7 and
                1 of ($payload_*)
            )
        )
}
