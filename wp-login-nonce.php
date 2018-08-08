<?php
/**
 * Add a nonce to WP Login form
 *
 * @author      Per Soderlind
 * @copyright   2018 Per Soderlind
 * @license     GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name: Add a nonce to WP Login form
 * Plugin URI: https://github.com/soderlind/wp-login-nonce
 * GitHub Plugin URI: https://github.com/soderlind/wp-login-nonce
 * Description: Use a nonce to prevent Login CSRF/XSRF.
 * Version:     0.0.1
 * Author:      Per Soderlind
 * Author URI:  https://soderlind.no
 * Text Domain: dss-login-nonce
 * License:     GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

namespace Soderlind\Admin\login;

add_action( 'login_form', __NAMESPACE__ . '\login_form_nonce_field' );
add_filter( 'authenticate', __NAMESPACE__ . '\login_form_nonce_field_validate', 99 );

function login_form_nonce_field() {
	wp_nonce_field( 'login-nonce', 'login-security' );
}

function login_form_nonce_field_validate( $user ) {
	if ( ! isset( $_POST['login-security'] ) || ! wp_verify_nonce( $_POST['login-security'], 'login-nonce' ) ) {
		$user = new \WP_Error( 'login-nonce', '<strong>ERROR</strong>: Invalid nonce' );
	}
	return $user;
}