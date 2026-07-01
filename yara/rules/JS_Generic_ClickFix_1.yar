/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule JS_Generic_ClickFix_1
{
    meta:
        author = "Caileb Murphy"
        company = "Webspec"
        company_site = "https://www.webspec.com/"

        copyright = "Copyright 2026 Webspec Design, LLC"
        license = "CC BY 4.0"
        yarahub_license = "CC BY 4.0"
        license_url = "https://creativecommons.org/licenses/by/4.0/"
        date = "2026-06-15"
        tlp = "clear"
        yarahub_rule_matching_tlp = "clear"
        yarahub_rule_sharing_tlp = "clear"
        yarahub_uuid = "0fb4e2a2-1f91-4da7-9b35-dd148195ada6"
        yarahub_reference_md5 = "1cb1271b43fd1e22df263a349470a839"

        description = "Detects ClickFix/fake CAPTCHA JavaScript that writes to clipboard and instructs the user to run a Windows command"

        family = "clickfix"
        confidence = "high"
        fp_risk = "low"

    strings:
        /* Clipboard write primitives */
        $clip_api_1 = "clipboard.writeText" ascii nocase
        $clip_api_2 = "navigator['clipboard']['writeText']" ascii
        $clip_api_3 = "navigator[\"clipboard\"][\"writeText\"]" ascii
        $clip_rx_1  = /navigator[ \t\r\n]*(\.[ \t\r\n]*clipboard|\[[ \t\r\n]*['"]clipboard['"][ \t\r\n]*\])[ \t\r\n]*(\.[ \t\r\n]*writeText|\[[ \t\r\n]*['"]writeText['"][ \t\r\n]*\])/ ascii
        $clip_legacy_1 = "execCommand('copy')" ascii nocase
        $clip_legacy_2 = "execCommand(\"copy\")" ascii nocase
        $clip_item = "ClipboardItem" ascii

        /* Fake verification / CAPTCHA lure, handles literal spaces and JS \x20 */
        $lure_verify_human =
            /Verify(\\x20|[ \t\r\n])+you(\\x20|[ \t\r\n])+are(\\x20|[ \t\r\n])+human/ ascii nocase

        $lure_not_robot =
            /not(\\x20|[ \t\r\n])+robot/ ascii nocase

        $lure_captcha      = "captcha" ascii nocase
        $lure_captcha_css  = "captcha-css" ascii nocase
        $lure_verification = "verification" ascii nocase
        $lure_cloudflare   = "Cloudflare" ascii nocase

        $lure_ray_id =
            /Ray(\\x20|[ \t\r\n])*ID/ ascii nocase

        $lure_perf_sec =
            /Performance(\\x20|[ \t\r\n])+and(\\x20|[ \t\r\n])+security/ ascii nocase

        /* ClickFix instructions, handles literal spaces and JS \x20 */
        $instr_complete_steps =
            /Complete(\\x20|[ \t\r\n])+these(\\x20|[ \t\r\n])+verification(\\x20|[ \t\r\n])+steps/ ascii nocase

        $instr_keyboard = "keyboard" ascii nocase

        $instr_win_key =
            /Win(dows)?(\\x20|[ \t\r\n])+key/ ascii nocase

        $instr_win_r =
            /Win(dows)?(\\x20|[ \t\r\n])*(key)?(\\x20|[ \t\r\n])*(\+|plus)(\\x20|[ \t\r\n])*R/ ascii nocase

        $instr_run_dialog =
            /Run(\\x20|[ \t\r\n])+dialog/ ascii nocase

        $instr_ver_window =
            /verification(\\x20|[ \t\r\n])+window/ ascii nocase

        $instr_ctrl_key =
            /Ctrl(\\x20|[ \t\r\n])+key/ ascii nocase

        $instr_ctrl_v =
            /Ctrl(\\x20|[ \t\r\n])*(\+|plus)(\\x20|[ \t\r\n])*V/ ascii nocase

        $instr_press_ctrl =
            /press(\\x20|[ \t\r\n])+Ctrl/ ascii nocase

        $instr_paste = "paste" ascii nocase

        $instr_enter_key =
            /Enter(\\x20|[ \t\r\n])+key/ ascii nocase

        $instr_press_enter =
            /Press(\\x20|[ \t\r\n])+Enter/ ascii nocase

        /* Windows shell / execution command indicators */
        $cmd_shell_1 =
            /cmd(\.exe)?(\\x20|[ \t\r\n])+\/(c|k)/ ascii nocase

        $cmd_shell_2 =
            /cmd(\.exe)?(\\x20|[ \t\r\n])+\/v:on/ ascii nocase

        $cmd_shell_3 =
            /start(\\x20|[ \t\r\n])+["']?["']?(\\x20|[ \t\r\n])+\/min/ ascii nocase

        /* LOLBins / execution utilities */
        $lolbin_mshta     = "mshta" ascii nocase
        $lolbin_powershell = "powershell" ascii nocase
        $lolbin_pwsh      = "pwsh" ascii nocase
        $lolbin_wscript   = "wscript" ascii nocase
        $lolbin_cscript   = "cscript" ascii nocase
        $lolbin_rundll32  = "rundll32" ascii nocase
        $lolbin_regsvr32  = "regsvr32" ascii nocase
        $lolbin_certutil  = "certutil" ascii nocase
        $lolbin_bitsadmin = "bitsadmin" ascii nocase
        $lolbin_msiexec   = "msiexec" ascii nocase

        /* Download / staging utilities */
        $dl_curl_1 =
            /curl(\.exe)?(\\x20|[ \t\r\n])/ ascii nocase

        $dl_iwr_1  = "Invoke-WebRequest" ascii nocase
        $dl_iwr_2  = "iwr " ascii nocase
        $dl_wget   = "wget " ascii nocase
        $dl_webclient = "DownloadString" ascii nocase
        $dl_downloadfile = "DownloadFile" ascii nocase

        /* PowerShell abuse */
        $ps_encoded_1 = "-EncodedCommand" ascii nocase
        $ps_encoded_2 = "-enc " ascii nocase
        $ps_hidden_1  = "-WindowStyle Hidden" ascii nocase
        $ps_hidden_2  = "-w hidden" ascii nocase
        $ps_bypass    = "ExecutionPolicy Bypass" ascii nocase
        $ps_nop       = "-nop" ascii nocase

        /* Local staging paths */
        $path_localappdata_1 = "%LocalAppData%" ascii nocase
        $path_localappdata_2 = "$env:LOCALAPPDATA" ascii nocase
        $path_appdata_1      = "%AppData%" ascii nocase
        $path_appdata_2      = "$env:APPDATA" ascii nocase
        $path_temp_1         = "%TEMP%" ascii nocase
        $path_temp_2         = "$env:TEMP" ascii nocase

        /* cmd obfuscation often used in ClickFix payloads */
        $obf_delayed_1 = "/v:on" ascii nocase
        $obf_substr_1  = ":~" ascii
        $obf_set_1     = "set " ascii nocase
        $obf_callbang  = "call !" ascii nocase
        $obf_bang_substr =
            /![A-Za-z0-9_]+:~[0-9]+,[0-9]+!/ ascii

        /* DOM takeover / overlay behavior */
        $dom_body = "document.body" ascii nocase
        $dom_style_1 = "createElement('style')" ascii
        $dom_style_2 = "createElement(\"style\")" ascii
        $dom_create_root = "createRoot" ascii nocase
        $dom_append_child = "appendChild" ascii nocase
        $dom_remove_styles =
            /querySelectorAll[ \t\r\n]*\([ \t\r\n]*['"]link\[rel=['"]?stylesheet['"]?\], style['"]/ ascii nocase

    condition:
        filesize < 3MB and

        /* clipboard write is mandatory */
        1 of ($clip_*) and

        /* fake CAPTCHA / verification lure */
        2 of ($lure_*) and

        /* user is instructed to open Run / paste / press Enter */
        (
            (
                1 of ($instr_win_key, $instr_win_r, $instr_run_dialog, $instr_ver_window) and
                1 of ($instr_ctrl_key, $instr_ctrl_v, $instr_press_ctrl, $instr_paste) and
                1 of ($instr_enter_key, $instr_press_enter)
            )
            or
            (
                $instr_complete_steps and
                $instr_keyboard and
                2 of ($instr_win_key, $instr_ctrl_key, $instr_enter_key, $instr_paste)
            )
        ) and

        /*
           Either the pasted Windows command is visible,
           or the page is a strong ClickFix UI where the command may be built/decoded at runtime.
        */
        (
            (
                1 of ($cmd_shell_*) and
                (
                    1 of ($lolbin_*) or
                    1 of ($dl_*) or
                    1 of ($ps_*) or
                    2 of ($obf_*)
                )
            )
            or
            (
                1 of ($lolbin_*) and
                1 of ($dl_*)
            )
            or
            (
                2 of ($ps_*) and
                (1 of ($path_*) or 1 of ($dl_*))
            )
            or
            (
                $instr_complete_steps and
                1 of ($instr_win_key, $instr_win_r, $instr_run_dialog) and
                1 of ($instr_ctrl_key, $instr_ctrl_v, $instr_paste) and
                1 of ($instr_enter_key, $instr_press_enter)
            )
        ) and

        /* extra confidence: local staging, cmd obfuscation, or DOM takeover */
        (
            1 of ($path_*) or
            2 of ($obf_*) or
            (
                $dom_body and
                1 of ($dom_style_*) and
                ($dom_create_root or $dom_append_child or $dom_remove_styles)
            )
        )
}
