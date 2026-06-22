/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule trafficredirect_Takeover_Redirect
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
        yarahub_reference_md5 = "f9d61641efc8a8ae1ad980034b7feed2"

        description = "Detects trafficredirect-style PHP redirects using remote config, cookie gating, cache state, and emitted browser redirect"

        family = "takeover_redirect"
        confidence = "high"
        fp_risk = "low"

    strings:
        $php = "<?php" ascii

        /* Remote fetch capability */
        $curl_init   = "curl_init" ascii nocase
        $curl_setopt = "curl_setopt" ascii nocase
        $curl_exec   = "curl_exec" ascii nocase
        $curl_ret    = "CURLOPT_RETURNTRANSFER" ascii
        $curl_url    = "CURLOPT_URL" ascii
        $fgc         = "file_get_contents" ascii nocase
        $https       = "https://" ascii nocase
        $http        = "http://" ascii nocase

        /* Cookie-gated redirect behavior */
        $cookie_read = "$_COOKIE" ascii
        $setcookie   = "setcookie" ascii nocase

        /* Local cache / state */
        $file_put    = "file_put_contents" ascii nocase
        $file_exists = "file_exists" ascii nocase
        $filemtime   = "filemtime" ascii nocase
        $filesize    = "filesize" ascii nocase
        $md5         = "md5(" ascii nocase

        /* Encoding often used to hide cached target or redirect JS */
        $b64_dec     = "base64_decode" ascii nocase
        $b64_enc     = "base64_encode" ascii nocase

        /* Remote config parsing */
        $json_decode = "json_decode" ascii nocase
        $preg_match  = "preg_match" ascii nocase
        $preg_all    = "preg_match_all" ascii nocase

        /* Literal JS redirect sinks */
        $script_lit  = "<script" ascii nocase
        $loc_replace = "window.location.replace" ascii nocase
        $loc_href    = "window.location.href" ascii nocase
        $loc_assign  = "window.location.assign" ascii nocase
        $doc_location = "document.location" ascii nocase

        /* Base64-encoded redirect primitives */
        $b64_script_open  = "PHNjcmlwdD4" ascii      /* <script> */
        $b64_script_close = "PC9zY3JpcHQ+" ascii    /* </script> */
        $b64_window_location = "d2luZG93LmxvY2F0aW9u" ascii /* window.location */
        $b64_location_href   = "bG9jYXRpb24uaHJlZg" ascii   /* location.href-ish */

    condition:
        filesize < 2MB and
        $php and

        /* Trafficredirect loaders keep fetch, visitor gate, parse/cache, and
           redirect code close together. Legitimate plugins may contain all of
           these primitives spread across unrelated features. */
        (
            for any si in (1..#script_lit) : (
                /* has nearby network config retrieval */
                (
                    (
                        $curl_setopt and
                        $curl_exec and
                        ($curl_ret or $curl_url) and
                        for any ri in (1..#curl_init) : (
                            (@curl_init[ri] <= @script_lit[si] and @script_lit[si] - @curl_init[ri] < 16384) or
                            (@script_lit[si] < @curl_init[ri] and @curl_init[ri] - @script_lit[si] < 16384)
                        )
                    )
                    or
                    (
                        ($https or $http) and
                        for any ri in (1..#fgc) : (
                            (@fgc[ri] <= @script_lit[si] and @script_lit[si] - @fgc[ri] < 16384) or
                            (@script_lit[si] < @fgc[ri] and @fgc[ri] - @script_lit[si] < 16384)
                        )
                    )
                ) and

                /* gates visitors with nearby cookies */
                (
                    for any ci in (1..#cookie_read) : (
                        (@cookie_read[ci] <= @script_lit[si] and @script_lit[si] - @cookie_read[ci] < 8192) or
                        (@script_lit[si] < @cookie_read[ci] and @cookie_read[ci] - @script_lit[si] < 8192)
                    )
                ) and
                (
                    for any ci in (1..#setcookie) : (
                        (@setcookie[ci] <= @script_lit[si] and @script_lit[si] - @setcookie[ci] < 8192) or
                        (@script_lit[si] < @setcookie[ci] and @setcookie[ci] - @script_lit[si] < 8192)
                    )
                ) and

                /* either caches/refreshes target or parses remote config */
                (
                    (
                        1 of ($file_exists, $filemtime, $filesize, $md5, $b64_enc, $b64_dec) and
                        for any pi in (1..#file_put) : (
                            (@file_put[pi] <= @script_lit[si] and @script_lit[si] - @file_put[pi] < 8192) or
                            (@script_lit[si] < @file_put[pi] and @file_put[pi] - @script_lit[si] < 8192)
                        )
                    )
                    or
                    (
                        for any pi in (1..#b64_dec) : (
                            (@b64_dec[pi] <= @script_lit[si] and @script_lit[si] - @b64_dec[pi] < 8192) or
                            (@script_lit[si] < @b64_dec[pi] and @b64_dec[pi] - @script_lit[si] < 8192)
                        )
                    )
                    or
                    (
                        ($json_decode or $preg_match or $preg_all) and
                        for any pi in (1..#json_decode) : (
                            (@json_decode[pi] <= @script_lit[si] and @script_lit[si] - @json_decode[pi] < 8192) or
                            (@script_lit[si] < @json_decode[pi] and @json_decode[pi] - @script_lit[si] < 8192)
                        )
                    )
                ) and

                /* emits browser redirect, literal or base64-hidden */
                (
                    (
                        for any li in (1..#loc_replace) : (
                            (@loc_replace[li] <= @script_lit[si] and @script_lit[si] - @loc_replace[li] < 4096) or
                            (@script_lit[si] < @loc_replace[li] and @loc_replace[li] - @script_lit[si] < 4096)
                        )
                    )
                    or
                    (
                        for any li in (1..#loc_href) : (
                            (@loc_href[li] <= @script_lit[si] and @script_lit[si] - @loc_href[li] < 4096) or
                            (@script_lit[si] < @loc_href[li] and @loc_href[li] - @script_lit[si] < 4096)
                        )
                    )
                    or
                    (
                        for any li in (1..#loc_assign) : (
                            (@loc_assign[li] <= @script_lit[si] and @script_lit[si] - @loc_assign[li] < 4096) or
                            (@script_lit[si] < @loc_assign[li] and @loc_assign[li] - @script_lit[si] < 4096)
                        )
                    )
                    or
                    (
                        for any li in (1..#doc_location) : (
                            (@doc_location[li] <= @script_lit[si] and @script_lit[si] - @doc_location[li] < 4096) or
                            (@script_lit[si] < @doc_location[li] and @doc_location[li] - @script_lit[si] < 4096)
                        )
                    )
                )
            )
            or
            (
                $b64_dec and
                $b64_window_location and
                1 of ($b64_script_open, $b64_script_close, $b64_location_href) and
                (
                    $curl_setopt and
                    $curl_exec and
                    ($curl_ret or $curl_url) and
                    for any ri in (1..#curl_init) : (
                        (@curl_init[ri] <= @b64_window_location and @b64_window_location - @curl_init[ri] < 16384) or
                        (@b64_window_location < @curl_init[ri] and @curl_init[ri] - @b64_window_location < 16384)
                    )
                )
            )
        )
}
