<?php

/**
 * Plugin Name: SMS Login
 * Description: Integrates with Inforu to enable OTP-based login
 * Version: 1.1.0
 * Author: Alex Kovalev
 * License: GPL v2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: sms-login
 * Domain Path: /languages
 */

namespace SMSLogin;

// Basic security check
if (!defined('ABSPATH')) {
    exit;
}

class SMSLoginPlugin
{
    private const OTP_LENGTH = 6;
    private const OTP_EXPIRY = 300; // 5 minutes
    private const MAX_ATTEMPTS = 10;
    private const RATE_LIMIT_WINDOW = 3600; // 1 hour
    private const TEXT_DOMAIN = 'sms-login';

    private $inforu_api_key;
    private $inforu_sender;
    private $test_mode;

    public function __construct()
    {
        $this->init_settings();
        $this->init_hooks();
    }

    private function init_settings()
    {
        $this->inforu_api_key = defined('INFORU_API_KEY') ? INFORU_API_KEY : '';
        $this->inforu_sender = defined('INFORU_SENDER') ? INFORU_SENDER : 'SMSLogin';
        $this->test_mode = defined('SMS_LOGIN_TEST_MODE') ? SMS_LOGIN_TEST_MODE : false;
    }

    private function init_hooks()
    {
        add_action('plugins_loaded', [$this, 'load_plugin_textdomain']);
        
        //add_action('login_footer', [$this, 'render_login_form']);
        add_shortcode('sms_login_form', [$this, 'render_login_form_shortcode']);
        add_action('wp_ajax_nopriv_verify_phone', [$this, 'handle_phone_verification']);
        add_action('wp_ajax_nopriv_verify_otp', [$this, 'handle_otp_verification']);
    }
    
    public function load_plugin_textdomain() 
    {
        load_plugin_textdomain(
            self::TEXT_DOMAIN,
            false,
            dirname(plugin_basename(__FILE__)) . '/languages/'
        );
    }
    

    public function render_login_form_shortcode($atts = []) {
        if (is_user_logged_in()) {
            return '';
        }
    
        wp_enqueue_script('sms-login', plugins_url('js/sms-login.js', __FILE__), ['jquery'], '1.1.0', true);
        wp_localize_script('sms-login', 'smsLoginAjax', [
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sms_login_nonce')
        ]);
    
        ob_start();
        include plugin_dir_path(__FILE__) . 'templates/login-form.php';
        return ob_get_clean();
    }

    public function render_login_form()
    {
        $client_ip = $this->get_client_ip();
        $transient_key = $this->generate_transient_key($client_ip);

        wp_enqueue_script('sms-login', plugins_url('js/sms-login.js', __FILE__), ['jquery'], '1.1.0', true);
        wp_localize_script('sms-login', 'smsLoginAjax', [
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sms_login_nonce')
        ]);

        include plugin_dir_path(__FILE__) . 'templates/login-form.php';
    }

    public function handle_phone_verification()
    {
        check_ajax_referer('sms_login_nonce', 'nonce');

        $phone = $this->sanitize_phone_number($_POST['phone'] ?? '');
        if (empty($phone)) {
            wp_send_json_error(['message' => __('Invalid phone number', self::TEXT_DOMAIN)]);
        }

        if ($this->is_rate_limited('phone_verification', self::MAX_ATTEMPTS)) {
            wp_send_json_error(['message' => __('Too many attempts. Please try again later.', self::TEXT_DOMAIN)]);
        }

        $user = $this->get_user_by_phone($phone);
        if (!$user) {
            wp_send_json_error(['message' => __('No user found with this phone number', self::TEXT_DOMAIN)]);
        }

        $otp = $this->generate_otp();
        $sent = $this->send_otp($phone, $otp);

        if (!$sent) {
            wp_send_json_error(['message' => __('Failed to send OTP', self::TEXT_DOMAIN)]);
        }

        $this->store_otp_data($phone, $otp, $user->ID);
        wp_send_json_success(['message' => __('OTP sent successfully', self::TEXT_DOMAIN)]);
    }

    public function handle_otp_verification()
    {
        check_ajax_referer('sms_login_nonce', 'nonce');

        $otp = $this->sanitize_number($_POST['otp'] ?? '');
        if (empty($otp)) {
            wp_send_json_error(['message' => __('Invalid OTP', self::TEXT_DOMAIN)]);
        }

        if ($this->is_rate_limited('otp_verification', self::MAX_ATTEMPTS)) {
            wp_send_json_error(['message' => __('Too many attempts. Please try again later.', self::TEXT_DOMAIN)]);
        }

        $stored_data = $this->get_stored_otp_data();
        if (!$stored_data || $stored_data['otp'] !== $otp) {
            wp_send_json_error(['message' => __('Invalid or expired OTP', self::TEXT_DOMAIN)]);
        }

        $this->login_user($stored_data['user_id']);
        $this->clear_stored_data();

        wp_send_json_success(['redirect_url' => home_url()]);
    }

    private function get_client_ip() {
        $ip = '';
        
        // Check for forwarded IP first
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim(current($forwarded_ips)); // Get first IP in list
        }
        // If no forwarded IP, use REMOTE_ADDR
        elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        // Validate IP address
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    private function generate_transient_key($identifier)
    {
        return wp_hash($identifier . AUTH_SALT);
    }

    private function sanitize_phone_number($phone)
    {
        $phone = preg_replace('/[^0-9+]/', '', $phone);
        return preg_match('/^\d{10}$/', $phone) ? $phone : '';
    }

    private function sanitize_number($input)
    {
        return preg_replace('/[^0-9]/', '', $input);
    }

    private function generate_otp()
    {
        return sprintf("%0" . self::OTP_LENGTH . "d", random_int(0, pow(10, self::OTP_LENGTH) - 1));
    }

    private function send_otp($phone, $otp)
    {
        if ($this->test_mode) {
            error_log("Test Mode - OTP for $phone: $otp");
            return true;
        }
        
        $message = sprintf(__('Your login code is: %s', self::TEXT_DOMAIN), $otp);

        $args = [
            'body' => wp_json_encode([
                'Data' => [
                    "Message" => $message,
                    "Recipients" => [
                        ["Phone" => $phone]
                    ],
                    "Settings" => [
                        "Sender" => $this->inforu_sender
                    ]
                ]
            ]),
            'headers' => [
                'Authorization' => 'Basic ' . $this->inforu_api_key,
                'Content-Type' => 'application/json'
            ],
            'timeout' => 15,
            'sslverify' => true
        ];

        $response = wp_remote_post("https://capi.inforu.co.il/api/v2/SMS/SendSms", $args);

        if (is_wp_error($response)) {
            error_log("SMS Login - Failed to send OTP: " . $response->get_error_message());
            return false;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        $success = isset($body['StatusId']) && $body['StatusId'] === 1;

        if (!$success) {
            error_log(print_r($response, true));
        }

        return $success;
    }

    /**
     * Function excludes admins from search
     */
    private function get_user_by_phone($phone)
    {
        
        //contactphone_1
        
        $users = get_users([
            'meta_key' => 'contactphone_1',
            'meta_value' => '',
            'meta_compare' => '!=',  // get all users with non-empty phone
            'role__not_in' => ['administrator']
        ]);
        
        foreach($users as $user) {
            $current_phone = get_user_meta($user->ID, 'contactphone_1', true);
            
            // Sanitize it
            $sanitized_phone = $this->sanitize_number($current_phone);
            
            if ($phone === $sanitized_phone) {
                return $user;
            }
        }
        
    }

    private function store_otp_data($phone, $otp, $user_id)
    {
        $transient_key = $this->generate_transient_key($this->get_client_ip());
        set_transient($transient_key, [
            'phone' => $phone,
            'otp' => $otp,
            'user_id' => $user_id,
            'expires' => time() + self::OTP_EXPIRY
        ], self::OTP_EXPIRY);
    }

    private function get_stored_otp_data()
    {
        $transient_key = $this->generate_transient_key($this->get_client_ip());
        $data = get_transient($transient_key);
        return $data && $data['expires'] > time() ? $data : null;
    }

    private function clear_stored_data()
    {
        $transient_key = $this->generate_transient_key($this->get_client_ip());
        delete_transient($transient_key);
    }

    private function is_rate_limited($action, $max_attempts)
    {
        $key = $this->generate_transient_key($this->get_client_ip() . $action);
        $attempts = (int)get_transient($key) ?? 0;

        if ($attempts >= $max_attempts) {
            return true;
        }

        set_transient($key, $attempts + 1, self::RATE_LIMIT_WINDOW);
        return false;
    }

    private function login_user($user_id)
    {
        $user = get_user_by('id', $user_id);
        if (!$user) {
            return false;
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        do_action('wp_login', $user->user_login, $user);

        return true;
    }
}


add_action('plugins_loaded', function () {
    new SMSLoginPlugin();
}, 0); 


