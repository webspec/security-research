/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule HTAccess_Image_Extension_PHP_Handler_IOC
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
        yarahub_uuid = "7f653829-98a6-4ea7-9ca6-4a1620900479"
        yarahub_reference_md5 = "6bb6f03dafff71bf7a91df2af466f673"

        description = "Detects .htaccess handler rules that make image extensions execute as PHP"

        family = "wp_persistence"
        confidence = "very-high"
        fp_risk = "very-low"

    strings:
        /* Direct handler mapping: AddHandler/AddType ... .jpg/.png/etc */
        $addhandler_image_php =
            /AddHandler[ \t\r\n]+(application\/x-httpd-(ea-)?php[0-9]*|x-httpd-(ea-)?php[0-9]*|php[0-9]*-script|php-script)[^\r\n#]{0,256}\.(jpe?g|png|gif|webp|ico|bmp|avif|svg)\b/ ascii nocase

        $addtype_image_php =
            /AddType[ \t\r\n]+(application\/x-httpd-(ea-)?php[0-9]*|application\/php|text\/x-php)[^\r\n#]{0,256}\.(jpe?g|png|gif|webp|ico|bmp|avif|svg)\b/ ascii nocase

        /* FilesMatch/Files wrapper around image extensions plus PHP handler */
        $filesmatch_image =
            /<Files(Match)?[^>]{0,512}\.(jpe?g|png|gif|webp|ico|bmp|avif|svg)[^>]{0,512}>/ ascii nocase

        $sethandler_php =
            /SetHandler[ \t\r\n]+(application\/x-httpd-(ea-)?php[0-9]*|x-httpd-(ea-)?php[0-9]*|php[0-9]*-script|php-script|proxy:unix:[^\r\n]+php[^\r\n]+fcgi:\/\/localhost)/ ascii nocase

        $forcetype_php =
            /ForceType[ \t\r\n]+(application\/x-httpd-(ea-)?php[0-9]*|application\/php|text\/x-php)/ ascii nocase

    condition:
        filesize < 2MB and
        (
            $addhandler_image_php or
            $addtype_image_php or
            (
                $filesmatch_image and
                1 of ($sethandler_php, $forcetype_php)
            )
        )
}
