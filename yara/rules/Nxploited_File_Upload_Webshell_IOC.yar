/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule Nxploited_File_Upload_Webshell_IOC
{
    meta:
        author = "Caileb Murphy"
        company = "Webspec"
        company_site = "https://www.webspec.com/"

        copyright = "Copyright 2026 Webspec Design, LLC"
        license = "CC BY 4.0"
        yarahub_license = "CC BY 4.0"
        license_url = "https://creativecommons.org/licenses/by/4.0/"
        date = "2026-06-22"
        tlp = "clear"
        yarahub_rule_matching_tlp = "clear"
        yarahub_rule_sharing_tlp = "clear"
        yarahub_reference_md5 = "7c61b52f9d46b7819d06d456e0bf5813"

        description = "Detects the Nxploited PHP upload webshell by its branding and same-directory upload behavior"

        family = "webshell"
        confidence = "very-high"
        fp_risk = "very-low"

    strings:
        $php = "<?php" ascii

        /* Nxploited branding and UI text */
        $brand_comment = "// Nxploited" ascii
        $title = "<title>Nxploited" ascii
        $heading = "<span>Nx</span>ploited" ascii
        $select_prompt = "Click to select a file" ascii
        $browse_label = "&#128194; Browse" ascii

        /* Direct upload handling used by this sample */
        $post_file_gate =
            /isset[ \t\r\n]*\([ \t\r\n]*\$_FILES[ \t\r\n]*\[[ \t\r\n]*['"]file['"][ \t\r\n]*\][ \t\r\n]*\)/ ascii

        $files_file_assignment =
            /\$[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*=[ \t\r\n]*\$_FILES[ \t\r\n]*\[[ \t\r\n]*['"]file['"][ \t\r\n]*\]/ ascii

        $same_dir_dest =
            /__DIR__[ \t\r\n]*\.[ \t\r\n]*['"]\/['"][ \t\r\n]*\.[ \t\r\n]*basename[ \t\r\n]*\(/ ascii

        $move_upload =
            /move_uploaded_file[ \t\r\n]*\([ \t\r\n]*\$[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*\[[ \t\r\n]*['"]tmp_name['"][ \t\r\n]*\]/ ascii

        $upload_success = "File uploaded:" ascii
        $upload_fail = "Failed to move file." ascii

    condition:
        filesize < 256KB and
        $php and
        2 of ($brand_comment, $title, $heading) and
        1 of ($select_prompt, $browse_label) and
        $post_file_gate and
        $files_file_assignment and
        $same_dir_dest and
        $move_upload and
        1 of ($upload_success, $upload_fail)
}
