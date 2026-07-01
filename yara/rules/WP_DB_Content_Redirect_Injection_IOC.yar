/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule WP_DB_Content_Redirect_Injection_IOC
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
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "87884599-3a07-4536-bd9e-9ecbefaf5d78"
        yarahub_reference_md5 = "696fce4e80f0c2c31ff9c1f7db5167c6"

        description = "Detects PHP code updating WordPress database content or options with external script, iframe, or redirect payloads"

        family = "wp_injection"
        confidence = "very-high"
        fp_risk = "very-low"

    strings:
        $php = "<?php" ascii

        /* WordPress DB write surfaces */
        $wpdb_query = "$wpdb->query" ascii
        $wpdb_update = "$wpdb->update" ascii
        $sql_update = /UPDATE[ \t\r\n]+[`'"]?([A-Za-z0-9_]+_)?(posts|options)[`'"]?[ \t\r\n]+SET/ ascii nocase
        $sql_replace = /REPLACE[ \t\r\n]+INTO[ \t\r\n]+[`'"]?([A-Za-z0-9_]+_)?(posts|options)[`'"]?/ ascii nocase

        /* WordPress target fields/tables */
        $post_content = "post_content" ascii nocase
        $option_value = "option_value" ascii nocase
        $wp_posts = "wp_posts" ascii nocase
        $wp_options = "wp_options" ascii nocase
        $wpdb_posts = "$wpdb->posts" ascii
        $wpdb_options = "$wpdb->options" ascii

        /* External redirect/injection payloads */
        $payload_script_http =
            /<script[^>]{0,512}src[ \t\r\n]*=[ \t\r\n]*[\\]?["']https?:\/\// ascii nocase

        $payload_iframe_http =
            /<iframe[^>]{0,512}src[ \t\r\n]*=[ \t\r\n]*[\\]?["']https?:\/\// ascii nocase

        $payload_meta_refresh =
            /http-equiv[ \t\r\n]*=[ \t\r\n]*["']refresh["'][^>]{0,512}https?:\/\// ascii nocase

        $payload_location_http =
            /\b(window\.)?location(\.href|\.replace|\.assign)?[ \t\r\n]*[=\(][ \t\r\n]*["']https?:\/\// ascii nocase

        $payload_js_uri =
            /javascript[ \t\r\n]*:[^"'\r\n]{0,512}(location|eval|atob|document\.cookie|window\.open)/ ascii nocase

    condition:
        filesize < 3MB and
        $php and
        (
            1 of ($wpdb_query, $wpdb_update, $sql_update, $sql_replace)
        ) and
        (
            1 of ($post_content, $option_value, $wp_posts, $wp_options, $wpdb_posts, $wpdb_options)
        ) and
        1 of ($payload_*)
}
