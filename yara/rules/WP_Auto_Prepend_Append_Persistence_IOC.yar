/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule WP_Auto_Prepend_Append_Persistence_IOC
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
        yarahub_uuid = "e82916d1-bbc5-4e96-8adf-5530e879d22e"
        yarahub_reference_md5 = "43c5adb1de31b3a7a100d1cac21d60ff"

        description = "Detects auto_prepend_file or auto_append_file persistence pointing at suspicious WordPress upload, temp, or hidden PHP paths"

        family = "wp_persistence"
        confidence = "very-high"
        fp_risk = "very-low"

    strings:
        /* php.ini/.user.ini syntax */
        $ini_auto_prepend =
            /auto_prepend_file[ \t]*=[ \t]*["']?[^"'\r\n;]{0,512}/ ascii nocase

        $ini_auto_append =
            /auto_append_file[ \t]*=[ \t]*["']?[^"'\r\n;]{0,512}/ ascii nocase

        /* .htaccess mod_php syntax */
        $htaccess_auto_prepend =
            /php_(admin_)?value[ \t]+auto_prepend_file[ \t]+["']?[^"'\r\n#]{0,512}/ ascii nocase

        $htaccess_auto_append =
            /php_(admin_)?value[ \t]+auto_append_file[ \t]+["']?[^"'\r\n#]{0,512}/ ascii nocase

        /* Suspicious target locations */
        $path_uploads_php =
            /wp-content\/uploads\/[^"'\r\n;#]{0,256}\.php[0-9]?\b/ ascii nocase

        $path_cache_php =
            /wp-content\/(cache|upgrade|uploads\/cache)\/[^"'\r\n;#]{0,256}\.php[0-9]?\b/ ascii nocase

        $path_tmp_php =
            /\/(tmp|var\/tmp|dev\/shm)\/[^"'\r\n;#]{1,256}\.php[0-9]?\b/ ascii nocase

        $path_hidden_php =
            /\/\.[A-Za-z0-9._-]{1,128}\.php[0-9]?\b/ ascii nocase

        $path_relative_hidden_php =
            /[ \t=]["']?\.[A-Za-z0-9._-]{1,128}\.php[0-9]?\b/ ascii nocase

    condition:
        filesize < 512KB and
        1 of ($ini_auto_*, $htaccess_auto_*) and
        1 of ($path_*)
}
