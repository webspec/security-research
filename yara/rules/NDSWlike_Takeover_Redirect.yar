/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule NDSWlike_Takeover_Redirect
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
        yarahub_uuid = "4efe1236-bfeb-4ce2-847d-f51d1c754417"
        yarahub_reference_md5 = "19942b5e9435879b6e1f125a2cba76f1"

        description = "Detects NDSW-like JavaScript redirect loaders using undefined guards, odd-index decoding, and dynamic script or pixel loading"

        family = "takeover_redirect"
        confidence = "very-high"
        fp_risk = "low"

    strings:
        /*
           Matches:
           ;if(x===undefined){var x=true;(function(){
           ; if (x == undefined) { let x = true; (function(){
        */
        $guard_eq_undefined =
            /;[ \t\r\n]*if[ \t\r\n]*\([ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*={2,3}[ \t\r\n]*undefined[ \t\r\n]*\)[ \t\r\n]*\{[ \t\r\n]*(var|let|const)[ \t\r\n]+[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*=[ \t\r\n]*true[ \t\r\n]*;[ \t\r\n]*\([ \t\r\n]*function[ \t\r\n]*\([ \t\r\n]*\)[ \t\r\n]*\{/ ascii

        /*
           Matches:
           ;if(typeof x==="undefined"){var x=true;(function(){
        */
        $guard_typeof_undefined =
            /;[ \t\r\n]*if[ \t\r\n]*\([ \t\r\n]*typeof[ \t\r\n]+[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*={2,3}[ \t\r\n]*["']undefined["'][ \t\r\n]*\)[ \t\r\n]*\{[ \t\r\n]*(var|let|const)[ \t\r\n]+[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*=[ \t\r\n]*true[ \t\r\n]*;[ \t\r\n]*\([ \t\r\n]*function[ \t\r\n]*\([ \t\r\n]*\)[ \t\r\n]*\{/ ascii

        /* Odd index decoder */
        $odd_eq_one =
            /if[ \t\r\n]*\([ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*%[ \t\r\n]*2[ \t\r\n]*={2,3}[ \t\r\n]*1[ \t\r\n]*\)/ ascii

        $odd_truthy =
            /if[ \t\r\n]*\([ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*%[ \t\r\n]*2[ \t\r\n]*\)/ ascii

        /* Reverse loop */
        $rev_loop_var =
            /for[ \t\r\n]*\([ \t\r\n]*(var|let)[ \t\r\n]+[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*=[ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}\.length[ \t\r\n]*-[ \t\r\n]*1[ \t\r\n]*;[ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}[ \t\r\n]*>=[ \t\r\n]*0[ \t\r\n]*;[ \t\r\n]*[A-Za-z_$][A-Za-z0-9_$]{0,64}--[ \t\r\n]*\)/ ascii

        /* Script injection */
        $script_create1 = "createElement('script')" ascii
        $script_create2 = "createElement(\"script\")" ascii
        $script_anchor1 = "getElementsByTagName('script')" ascii
        $script_anchor2 = "getElementsByTagName(\"script\")" ascii
        $dom_insert1    = "insertBefore" ascii
        $dom_insert2    = "appendChild" ascii
        $async_true     = ".async=true" ascii
        $script_type    = "text/javascript" ascii nocase

        /* src assignment variants */
        $src_dot        = /\.src[ \t\r\n]*=/ ascii
        $src_bracket    = /\[[ \t\r\n]*["']src["'][ \t\r\n]*\][ \t\r\n]*=/ ascii
        $src_setattr    = /setAttribute[ \t\r\n]*\([ \t\r\n]*["']src["'][ \t\r\n]*,/ ascii

        /* Canvas/image pixel loader variant */
        $canvas_create1 = "createElement('canvas')" ascii
        $canvas_create2 = "createElement(\"canvas\")" ascii
        $local_storage  = "localStorage" ascii
        $new_image      = "new Image()" ascii
        $cross_origin   = "crossOrigin" ascii
        $get_context    = "getContext" ascii
        $draw_image     = "drawImage" ascii
        $get_image_data = "getImageData" ascii
        $json_parse     = "JSON.parse" ascii
        $from_char_code = "String.fromCharCode" ascii

    condition:
        filesize < 2MB and
        1 of ($guard_*) and
        1 of ($odd_*) and
        $rev_loop_var and
        (
            /*
               Direct remote script loader variants
            */
            (
                1 of ($script_create*) and
                1 of ($src_*) and
                1 of ($dom_insert*) and
                (
                    1 of ($script_anchor*) or
                    $async_true or
                    $script_type
                )
            )

            or

            /*
               Canvas / tracking pixel / JSON-to-script variants
            */
            (
                1 of ($canvas_create*) and
                $local_storage and
                $new_image and
                $get_context and
                $get_image_data and
                $json_parse and
                ($draw_image or $cross_origin or $from_char_code) and
                1 of ($script_create*) and
                1 of ($src_*) and
                1 of ($dom_insert*)
            )
        )
}
