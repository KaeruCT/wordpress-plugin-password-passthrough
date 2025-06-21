<?php
/*
Plugin Name: Password URL Pass-through
Description: This plugin allows passwords for password-protected pages/posts to be passed directly through the URL. The query string parameter that should contain the password is <strong>pw</strong>. For example, if the URL of your post is <strong>http://myblog.com/password-protected-page/</strong> and the password is <strong>PASSWORD</strong>, then just append <strong>?pw=PASSWORD</strong> to it. If the URL already contains a query string (for example, <strong>http://myblog.com/?p=5</strong>), then be sure to append <strong>&pw=PASSWORD</strong> instead.
Version:     2.0.0
Author:      Andres Villarreal
Author URI:  https://andres.villarreal.co.cr
License: GPLv3 or later
 */

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

defined( 'ABSPATH' ) or die();

add_action( 'template_redirect', function () {
    if ( empty( $_GET['pw'] ) ) {
        return;
    }

    $post = get_post();
    $password = sanitize_text_field( wp_unslash( $_GET['pw'] ) );

    if ( $post && $post->post_password === $password ) {
        $expire = apply_filters( 'post_password_expires', time() + 10 * DAY_IN_SECONDS );
        require_once ABSPATH . WPINC . '/class-phpass.php';
        $hasher = new PasswordHash( 8, true );
        $hashed_password = $hasher->HashPassword( wp_unslash( $password ) );
        $secure = is_ssl();

        setcookie(
            'wp-postpass_' . COOKIEHASH,
            $hashed_password,
            $expire,
            COOKIEPATH,
            COOKIE_DOMAIN,
            $secure
        );

        $redirect_url = remove_query_arg( 'pw' );
        wp_safe_redirect( $redirect_url );
        exit;
    }
});
