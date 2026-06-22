/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule Apsheader_Takeover_Redirect_DBScan
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
        yarahub_reference_md5 = "413e06c00254b2b2d5b2047a50a3005f"

        description = "Detects DB-stored WPCode apsheader PHP loader or redirect injection"

        family = "takeover_redirect"
        confidence = "very-high"
        fp_risk = "low"

        db_scan = true

    strings:
        /* DB / WPCode context seen in SQL dumps, serialized options, and WP-CLI output. */
        $db_wpcode_option =
            "wpcode_snippets" ascii

        $db_wpcode_title =
            "Wp_footer_sets" ascii

        $db_wpcode_type_serialized =
            /s:9:\\?["']code_type\\?["'];s:3:\\?["']php\\?["']/ ascii

        $db_wpcode_location_serialized =
            /s:8:\\?["']location\\?["'];s:10:\\?["']everywhere\\?["']/ ascii

        $db_wpcode_autoinsert_serialized =
            /s:11:\\?["']auto_insert\\?["'];i:1/ ascii

        $db_wpcode_type_export =
            /['"]code_type['"][ \t\r\n]*=>[ \t\r\n]*['"]php['"]/ ascii

        $db_wpcode_location_export =
            /['"]location['"][ \t\r\n]*=>[ \t\r\n]*['"]everywhere['"]/ ascii

        $db_wpcode_autoinsert_export =
            /['"]auto_insert['"][ \t\r\n]*=>[ \t\r\n]*1/ ascii

        $db_wpcode_post_type =
            /['"]wpcode['"]/ ascii

        $db_wpcode_slug =
            "wp_footer_sets" ascii

        /*
           PHP loader portion, based on Apsheader_Takeover_Redirect with
           quote-escape tolerance for SQL/serialized DB values.
        */
        $php_error_reporting =
            /error_reporting[ \t\r\n]*\([ \t\r\n]*0[ \t\r\n]*\)/ ascii

        $php_strrev_chr =
            /strrev[ \t\r\n]*\([ \t\r\n]*chr[ \t\r\n]*\([0-9]{2,3}\)[ \t\r\n]*(\.[ \t\r\n]*chr[ \t\r\n]*\([0-9]{2,3}\)[ \t\r\n]*){3,16}\)/ ascii

        $php_post_o =
            /\$_POST[ \t\r\n]*\[[ \t\r\n]*\\?["']o\\?["'][ \t\r\n]*\]/ ascii

        $php_post_oo =
            /\$_POST[ \t\r\n]*\[[ \t\r\n]*\\?["']oo\\?["'][ \t\r\n]*\]/ ascii

        $php_md5_gate =
            /md5[ \t\r\n]*\([ \t\r\n]*\$_POST[ \t\r\n]*\[[ \t\r\n]*\\?["']o\\?["'][ \t\r\n]*\][ \t\r\n]*\)[ \t\r\n]*={2,3}/ ascii

        $php_tempnam =
            /tempnam[ \t\r\n]*\([ \t\r\n]*sys_get_temp_dir[ \t\r\n]*\(/ ascii

        $php_tag_frag =
            /\\?["']<\\?["'][ \t\r\n]*\.[ \t\r\n]*\\?["']\?\\?["'][ \t\r\n]*\.[ \t\r\n]*\\?["']ph\\?["'][ \t\r\n]*\.[ \t\r\n]*\\?["']p/ ascii

        $php_include =
            /@?include[ \t\r\n]*\([ \t\r\n]*\$[A-Za-z_][A-Za-z0-9_]{0,32}[ \t\r\n]*\)/ ascii

        $builder_get =
            /\.[ \t\r\n]*\\?["']get_\\?["'][ \t\r\n]*\./ ascii

        $builder_put =
            /\.[ \t\r\n]*\\?["']put_\\?["'][ \t\r\n]*\./ ascii

        $builder_base64 =
            /\\?["']ba\\?["'][ \t\r\n]*\.[ \t\r\n]*\$[A-Za-z_][A-Za-z0-9_]{0,32}[ \t\r\n]*\(/ ascii

        /* DB-stored apsheader redirect variant from the non-DB rule family. */
        $wp_apsheader =
            /function[ \t\r\n]+apsheader[ \t\r\n]*\([ \t\r\n]*\)/ ascii

        $wp_head_hook =
            /add_action[ \t\r\n]*\([ \t\r\n]*\\?["']wp_head\\?["'][ \t\r\n]*,[ \t\r\n]*\\?["']apsheader\\?["'][ \t\r\n]*\)/ ascii

        $js_xhr =
            "XMLHttpRequest" ascii

        $js_response =
            "responseText" ascii

        $js_create =
            "createElement" ascii

        $js_append =
            "appendChild" ascii

        $js_logged_in =
            "logged-in" ascii

        $js_pylon =
            "pylon" ascii

        $js_lander =
            "landers" ascii

        $js_click_key =
            "/click?key=" ascii

    condition:
        (
            /*
               DB context in the same buffer, when Yaraw scans whole rows or
               option_value strings.
            */
            (
                (
                    $db_wpcode_option or
                    $db_wpcode_title or
                    (
                        $db_wpcode_type_serialized and
                        $db_wpcode_location_serialized and
                        $db_wpcode_autoinsert_serialized
                    ) or
                    (
                        $db_wpcode_type_export and
                        $db_wpcode_location_export and
                        $db_wpcode_autoinsert_export
                    ) or
                    ($db_wpcode_post_type and $db_wpcode_slug)
                ) and
                (
                    (
                        $php_strrev_chr and
                        $php_post_o and
                        $php_post_oo and
                        $php_md5_gate and
                        $php_tempnam and
                        $php_tag_frag and
                        $php_include and
                        1 of ($php_error_reporting, $builder_get, $builder_put, $builder_base64)
                    ) or
                    (
                        $wp_apsheader and
                        $wp_head_hook and
                        $js_xhr and
                        3 of ($js_response, $js_create, $js_append, $js_logged_in, $js_pylon, $js_lander, $js_click_key)
                    )
                )
            ) or

            /*
               Some DB scanners pass only the code column. This remains DB-only
               through meta.db_scan and mirrors the non-DB PHP loader branch.
            */
            (
                $php_strrev_chr and
                $php_post_o and
                $php_post_oo and
                $php_md5_gate and
                $php_tempnam and
                $php_tag_frag and
                $php_include and
                2 of ($php_error_reporting, $builder_get, $builder_put, $builder_base64)
            )
        )
}
