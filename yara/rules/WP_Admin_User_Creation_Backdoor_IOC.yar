/*
 * SPDX-License-Identifier: CC-BY-4.0
 */

rule WP_Admin_User_Creation_Backdoor_IOC
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
        yarahub_uuid = "2f57e5c4-f7f7-421e-9b16-bc4909d7dcc2"
        yarahub_reference_md5 = "b1cf341ce4b5193a369836aaaac07388"

        description = "Detects WordPress code that creates or inserts administrator users from hook or request-controlled backdoor logic"

        family = "wp_backdoor"
        confidence = "very-high"
        fp_risk = "medium"

    strings:
        $php = "<?php" ascii

        /* WordPress user creation APIs */
        $wp_create_user = "wp_create_user" ascii nocase
        $wp_insert_user = "wp_insert_user" ascii nocase
        $wp_update_user = "wp_update_user" ascii nocase

        /* Direct database user creation/update */
        $wpdb_users = "$wpdb->users" ascii
        $wp_users_table = "wp_users" ascii nocase
        $insert_into = /INSERT[ \t\r\n]+INTO/ ascii nocase
        $user_pass = "user_pass" ascii nocase
        $wp_hash_password = "wp_hash_password" ascii nocase

        /* Administrator capability assignment */
        $role_arg_admin =
            /["']role["'][ \t\r\n]*=>[ \t\r\n]*["']administrator["']/ ascii nocase

        $set_role_admin =
            /->set_role[ \t\r\n]*\([ \t\r\n]*["']administrator["'][ \t\r\n]*\)/ ascii nocase

        $caps_admin_serialized =
            /a:1:\{s:13:["']administrator["'];b:1;\}/ ascii nocase

        $wp_capabilities = "wp_capabilities" ascii nocase
        $wp_user_level = "wp_user_level" ascii nocase
        $administrator = "administrator" ascii nocase

        /* Backdoor trigger surfaces */
        $req_get = "$_GET" ascii
        $req_post = "$_POST" ascii
        $req_request = "$_REQUEST" ascii
        $req_cookie = "$_COOKIE" ascii

        $hook_init =
            /add_action[ \t\r\n]*\([ \t\r\n]*["'](init|wp_loaded|admin_init|plugins_loaded|template_redirect)["']/ ascii nocase

    condition:
        filesize < 2MB and
        $php and
        (
            /*
               WP API creates/updates an administrator in request/hook-driven code.
            */
            (
                1 of ($wp_create_user, $wp_insert_user, $wp_update_user) and
                1 of ($role_arg_admin, $set_role_admin) and
                (
                    1 of ($req_*) or
                    $hook_init
                )
            )
            or

            /*
               Direct DB creation of wp_users plus admin capabilities/usermeta.
            */
            (
                1 of ($wpdb_users, $wp_users_table) and
                $insert_into and
                1 of ($user_pass, $wp_hash_password) and
                (
                    $caps_admin_serialized or
                    (
                        $wp_capabilities and
                        $administrator
                    ) or
                    (
                        $wp_user_level and
                        $administrator
                    )
                ) and
                (
                    1 of ($req_*) or
                    $hook_init
                )
            )
        )
}
