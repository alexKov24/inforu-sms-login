<!-- templates/login-form.php -->

<div class="sms-login-wrapper">
    <div id="message-box" class="message-box"></div>
    <form id="sms-login-form" method="post">
        <div id="phone-step">
            <h3><?php esc_html_e('Login with Phone Number', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></h3>
            <p>
                <label for="phone_number"><?php esc_html_e('Phone Number', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></label>
                <input type="text"
                    name="phone_number"
                    id="phone_number"
                    required
                    pattern="^\d{10}$"
                    title="<?php esc_attr_e('Please enter a valid phone number', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?>">
            </p>
            <button type="submit"><?php esc_html_e('Send OTP', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></button>
        </div>
        <div id="otp-step" style="display: none;">
            <h3><?php esc_html_e('Enter OTP', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></h3>
            <p>
                <label for="otp"><?php esc_html_e('One-Time Password', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></label>
                <input type="text"
                    name="otp"
                    id="otp"
                    pattern="[0-9]{6}"
                    title="<?php esc_attr_e('Please enter the 6-digit OTP', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?>">
            </p>
            <button type="submit"><?php esc_html_e('Verify & Login', \SMSLogin\SMSLoginPlugin::TEXT_DOMAIN); ?></button>
        </div>
    </form>
</div>