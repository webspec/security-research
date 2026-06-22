/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule Telegram_Channel_Fetch_IOC
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
        yarahub_reference_md5 = "826516d73b22dfeaa069867c76ac5898"

        description = "Detects PHP or JavaScript that fetches Telegram channel preview URLs under t.me/s/"

        family = "remote_loader"
        confidence = "high"
        fp_risk = "low"

    strings:
        /* File type / language anchors */
        $php_open = "<?php" ascii
        $js_script = "<script" ascii nocase
        $js_function = "function" ascii
        $js_arrow = "=>" ascii

        /* JavaScript network sinks */
        $js_fetch = "fetch" ascii
        $js_xhr = "XMLHttpRequest" ascii
        $js_axios_get = "axios.get" ascii nocase
        $js_ajax = "$.ajax" ascii
        $js_get = "$.get" ascii
        $js_import_scripts = "importScripts" ascii
        $js_request = "new Request" ascii
        $js_sendbeacon = "sendBeacon" ascii

        /* Clear Telegram channel preview fetches */
        $php_fgc_tme =
            /file_get_contents[ \t\r\n]*\([ \t\r\n]*["'](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $php_wp_remote_tme =
            /wp_remote_get[ \t\r\n]*\([ \t\r\n]*["'](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $php_fopen_tme =
            /fopen[ \t\r\n]*\([ \t\r\n]*["'](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $php_curl_setopt_tme =
            /curl_setopt[ \t\r\n]*\([^\r\n;]{0,512}CURLOPT_URL[^\r\n;]{0,512}(https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_fetch_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_xhr_tme =
            /\.open[ \t\r\n]*\([ \t\r\n]*["'`]GET["'`][^\r\n;)]{0,512}(https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_ajax_tme =
            /\$\.(ajax|get|getJSON)[ \t\r\n]*\([^\r\n;)]{0,512}(https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_axios_tme =
            /axios\.get[ \t\r\n]*\([ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_import_tme =
            /importScripts[ \t\r\n]*\([ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_request_tme =
            /new[ \t\r\n]+Request[ \t\r\n]*\([ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_sendbeacon_tme =
            /sendBeacon[ \t\r\n]*\([ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $php_fgc_b64_tme =
            /file_get_contents[ \t\r\n]*\([ \t\r\n]*base64_decode[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $php_wp_remote_b64_tme =
            /wp_remote_get[ \t\r\n]*\([ \t\r\n]*base64_decode[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $php_fopen_b64_tme =
            /fopen[ \t\r\n]*\([ \t\r\n]*base64_decode[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $php_curl_b64_tme =
            /curl_setopt[ \t\r\n]*\([^\r\n;]{0,512}CURLOPT_URL[^\r\n;]{0,512}base64_decode[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $js_fetch_atob_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*atob[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $js_xhr_atob_tme =
            /\.open[ \t\r\n]*\([ \t\r\n]*["'`]GET["'`][^\r\n;)]{0,512}atob[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $js_axios_atob_tme =
            /axios\.get[ \t\r\n]*\([ \t\r\n]*atob[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $js_beacon_atob_tme =
            /sendBeacon[ \t\r\n]*\([ \t\r\n]*atob[ \t\r\n]*\([ \t\r\n]*["'`](aHR0cHM6Ly90Lm1lL3Mv|aHR0cDovL3QubWUvcy8|dC5tZS9zLw)/ ascii nocase

        $js_fetch_hex_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*["'`]\\x74\\x2e\\x6d\\x65\\x2f\\x73\\x2f/ ascii nocase

        $js_fetch_unicode_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*["'`]\\u0074\\u002e\\u006d\\u0065\\u002f\\u0073\\u002f/ ascii nocase

        $js_fetch_charcode_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*String\.fromCharCode[ \t\r\n]*\([ \t\r\n]*116[ \t\r\n]*,[ \t\r\n]*46[ \t\r\n]*,[ \t\r\n]*109[ \t\r\n]*,[ \t\r\n]*101[ \t\r\n]*,[ \t\r\n]*47[ \t\r\n]*,[ \t\r\n]*115[ \t\r\n]*,[ \t\r\n]*47/ ascii

        $js_fetch_concat_tme =
            /fetch[ \t\r\n]*\([ \t\r\n]*["'`]t["'`][ \t\r\n]*\+[ \t\r\n]*["'`]\.me["'`][ \t\r\n]*\+[ \t\r\n]*["'`]\/s\// ascii

        /* Bounded same-block URL assignment and fetch patterns */
        $php_assign_then_fgc_tme =
            /\$[A-Za-z_][A-Za-z0-9_]{0,40}[ \t\r\n]*=[ \t\r\n]*["'](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $php_assign_then_fetch_api =
            /(file_get_contents|wp_remote_get|fopen)[ \t\r\n]*\([ \t\r\n]*\$[A-Za-z_][A-Za-z0-9_]{0,40}|curl_setopt[ \t\r\n]*\([^\r\n;]{0,256}CURLOPT_URL[^\r\n;]{0,128}\$[A-Za-z_][A-Za-z0-9_]{0,40}/ ascii nocase

        $js_assign_then_fetch_tme =
            /((var|let|const)[ \t\r\n]+)?[A-Za-z_$][A-Za-z0-9_$]{0,40}[ \t\r\n]*=[ \t\r\n]*["'`](https?:)?\\?\/\\?\/t(\.|\\x2e|\\u002e)me\\?\/s\\?\// ascii nocase

        $js_assign_then_fetch_api =
            /(fetch|axios\.get|importScripts|sendBeacon|\$\.(ajax|get|getJSON))[ \t\r\n]*\([ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,40}/ ascii nocase

    condition:
        filesize < 6MB and
        (
            (
                $php_open and
                (
                    1 of ($php_fgc_tme, $php_wp_remote_tme, $php_fopen_tme, $php_curl_setopt_tme, $php_fgc_b64_tme, $php_wp_remote_b64_tme, $php_fopen_b64_tme, $php_curl_b64_tme) or
                    (
                        for any i in (1..#php_assign_then_fgc_tme) : (
                            for any j in (1..#php_assign_then_fetch_api) : (
                                @php_assign_then_fetch_api[j] > @php_assign_then_fgc_tme[i] and
                                @php_assign_then_fetch_api[j] - @php_assign_then_fgc_tme[i] < 768
                            )
                        )
                    )
                )
            )
            or
            (
                1 of ($js_script, $js_function, $js_arrow, $js_fetch, $js_xhr, $js_axios_get, $js_ajax, $js_get, $js_import_scripts, $js_request, $js_sendbeacon) and
                (
                    1 of ($js_fetch_tme, $js_xhr_tme, $js_ajax_tme, $js_axios_tme, $js_import_tme, $js_request_tme, $js_sendbeacon_tme, $js_fetch_atob_tme, $js_xhr_atob_tme, $js_axios_atob_tme, $js_beacon_atob_tme, $js_fetch_hex_tme, $js_fetch_unicode_tme, $js_fetch_charcode_tme, $js_fetch_concat_tme) or
                    (
                        for any i in (1..#js_assign_then_fetch_tme) : (
                            for any j in (1..#js_assign_then_fetch_api) : (
                                @js_assign_then_fetch_api[j] > @js_assign_then_fetch_tme[i] and
                                @js_assign_then_fetch_api[j] - @js_assign_then_fetch_tme[i] < 768
                            )
                        )
                    )
                )
            )
        )
}
