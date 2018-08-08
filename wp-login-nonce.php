<?php
/**
 * Add a nonce to WP Login form
 *
 * @author      Per Soderlind
 * @copyright   2018 Per Soderlind
 * @license     GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name: Add a nonce to the WP Login form
 * Plugin URI: https://github.com/soderlind/wp-login-nonce
 * GitHub Plugin URI: https://github.com/soderlind/wp-login-nonce
 * Description: Use a nonce to prevent Login Cross-Site Request Forgery (CSRF).
 * Version:     0.0.3
 * Author:      Per Soderlind
 * Author URI:  https://soderlind.no
 * Text Domain: dss-login-nonce
 * License:     GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

namespace Soderlind\Admin\login;

add_action( 'login_form', __NAMESPACE__ . '\login_form_nonce_field' );
add_filter( 'authenticate', __NAMESPACE__ . '\login_form_nonce_field_validate', 99, 3 );
add_filter(
	'nonce_user_logged_out', function ( $uid = 0, $action = '' ) {
		if ( $action == 'nonceauth' ) {
			return 0;
		}

		return $uid;
	}, 100, 2
);

/**
 * Add a hidden nonce field to the login form.
 *
 * @return void
 */
function login_form_nonce_field() {
	$token = bin2hex( openssl_random_pseudo_bytes( 16 ) );
	setcookie( 'csrftoken', $token, time() + DAY_IN_SECONDS );

	wp_nonce_field( 'nonceid_' . $token, 'nonceauth' );
}

/**
 * Validate the nonce.
 *
 * If DUO Security 2FA is installed and activated, and this is the 2FA auth by DUO,
 * skip nonce validation.
 *
 * @param null|WP_User|WP_Error $user     WP_User if the user is authenticated. WP_Error or null otherwise.
 * @param string                $username Username or email address.
 * @param string                $password User password.
 * @return null|WP_User|WP_Error
 */
function login_form_nonce_field_validate( $user, $username, $password ) {
	// Don't validate nonce when doing secondary auth by DUO
	if ( function_exists( 'duo_auth_enabled' ) && duo_auth_enabled() && isset( $_POST['sig_response'] ) ) {
		return $user;
	}

	if ( ! isset( $_REQUEST['nonceauth'], $_COOKIE['csrftoken'] ) ) {
		return $user;
	}
	$nonce = $_REQUEST['nonceauth'];
	$token = $_COOKIE['csrftoken'];
	if ( ! wp_verify_nonce( $nonce, 'nonceid_' . $token ) ) {
		return new \WP_Error( 'nonceauth', '<strong>ERROR</strong>: Invalid nonce' );
	}
	return $user;
}
