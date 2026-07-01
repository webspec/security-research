/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule Apsheader_Takeover_Redirect
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
        yarahub_uuid = "7c350704-f85c-4521-ac44-73a9203eca7f"
        yarahub_reference_md5 = "413e06c00254b2b2d5b2047a50a3005f"

        description = "Detects WordPress apsheader redirect loaders using PHP chr/strrev staging and obfuscated JavaScript injection"

        family = "takeover_redirect"
        confidence = "very-high"
        fp_risk = "low"

    strings:
        /*
           PHP loader / staging behavior
        */
        $php_error_reporting =
            /error_reporting[ \t\r\n]*\([ \t\r\n]*0[ \t\r\n]*\)/ ascii

        $php_strrev_chr =
            /strrev[ \t\r\n]*\([ \t\r\n]*chr[ \t\r\n]*\([0-9]{2,3}\)[ \t\r\n]*(\.[ \t\r\n]*chr[ \t\r\n]*\([0-9]{2,3}\)[ \t\r\n]*){3,12}\)/ ascii

        $php_post_o =
            /\$_POST[ \t\r\n]*\[[ \t\r\n]*["']o["'][ \t\r\n]*\]/ ascii

        $php_post_oo =
            /\$_POST[ \t\r\n]*\[[ \t\r\n]*["']oo["'][ \t\r\n]*\]/ ascii

        $php_md5_gate =
            /md5[ \t\r\n]*\([ \t\r\n]*\$_POST[ \t\r\n]*\[[ \t\r\n]*["']o["'][ \t\r\n]*\][ \t\r\n]*\)[ \t\r\n]*={2,3}/ ascii

        $php_tempnam =
            "tempnam(sys_get_temp_dir()" ascii

        $php_include =
            /@?include[ \t\r\n]*\([ \t\r\n]*\$[A-Za-z_][A-Za-z0-9_]{0,32}[ \t\r\n]*\)/ ascii

        /*
           WordPress header injection
        */
        $wp_apsheader =
            /function[ \t\r\n]+apsheader[ \t\r\n]*\([ \t\r\n]*\)/ ascii

        $wp_head_hook =
            /add_action[ \t\r\n]*\([ \t\r\n]*["']wp_head["'][ \t\r\n]*,[ \t\r\n]*["']apsheader["'][ \t\r\n]*\)/ ascii

        /*
           Obfuscated JavaScript loader behavior
        */
        $js_decoder =
            /function[ \t\r\n]+_0x[0-9a-fA-F]{3,8}[ \t\r\n]*\(/ ascii

        $js_rotate =
            "while(!![])" ascii

        $js_httpget =
            /function[ \t\r\n]+httpGet[ \t\r\n]*\(/ ascii

        $js_xhr =
            "new XMLHttpRequest()" ascii

        $js_response =
            "responseTe" ascii

        $js_cookie =
            "logged-in" ascii

        $js_create =
            "createElem" ascii

        $js_append =
            "appendChil" ascii

        $js_script =
            "script" ascii

        /*
           Optional family fragments seen in this cluster
        */
        $frag_pylon =
            "pylon" ascii

        $frag_lander =
            "ande" ascii

        $frag_rs_t =
            "rs/t" ascii

        $frag_icu =
            ".icu" ascii

    condition:
        filesize < 2MB and
        (
            /*
               Full infected WordPress file
            */
            (
                $wp_apsheader and
                $wp_head_hook and
                2 of ($php_*) and
                5 of ($js_*)
            )

            or

            /*
               PHP loader portion
            */
            (
                $php_strrev_chr and
                $php_post_o and
                $php_post_oo and
                $php_md5_gate and
                $php_tempnam and
                $php_include
            )

            or

            /*
               JavaScript redirect portion
            */
            (
                $wp_apsheader and
                $wp_head_hook and
                $js_decoder and
                $js_rotate and
                $js_xhr and
                2 of ($js_create, $js_append, $js_response, $js_cookie, $js_script) and
                1 of ($frag_*)
            )
        )
}
