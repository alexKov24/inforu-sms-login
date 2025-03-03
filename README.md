# Inforu SMS Login

This is a simple login page for Inforu SMS.

## TODO

- Add a select for user field to be used for phone number. currently it uses 'contactphone_1'
- Add setting for OTP. Length, character set, etc.
- Add setting for SMS gateway. Currently it uses the default gateway.
- Add setting for SMS message. Currently it uses the default message.
- Add setting for SMS sender. Currently it uses the default sender.
- Add setting for user role to be used for login. Currently it uses all but administrators.

- Add setting for rate limit. Currently it deferantiates the users by ip address.

## Setup and Installation

1. make sure your users have 'contactphone_1' without it the plugin won't work
2. make sure you have the api key
3. define api key in your wp-config.php ```define('INFORU_API_KEY', 'your-api-key');```
4. define sender in your wp-config.php ```define('INFORU_SENDER', 'SMSLogin');```
5. define test mode in your wp-config.php ```define('SMS_LOGIN_TEST_MODE', true);```
6. user shortcode ```[sms_login_form]```