=== Password Passthrough ===
Contributors: KaeruCT
Donate link: https://liberapay.com/KaeruCT
Tags: password, protected, url, post, page
Requires at least: 5.4
Tested up to: 6.8.1
Stable tag: trunk
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html

This plugin allows passwords for password-protected pages/posts to be passed directly through the URL.

== Description ==

This plugin allows passwords for password-protected pages/posts to be passed directly through the URL.

The query string parameter that should contain the password is `pw`.

For example, if the URL of your post is `http://myblog.com/password-protected-page/` and the password is `PASSWORD`,
then just append `?pw=PASSWORD` to it.

If the URL already contains a query string (for example, `http://myblog.com/?p=5`), then be sure to append `&pw=PASSWORD` instead.

== Installation ==

In order to install the plugin, please follow these steps:

1. Upload `plugin-name.php` to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.

== Changelog ==

= 1.0 =
* First released version.

= 1.1.0 =
* Plugin now strips the pw parameter from the URL after the respective cookie has been stored by WordPress.

= 2.0.0 =
* Updates to work with WordPress 5.4 and up to 6.8.1 - thanks to
  @grappler !
