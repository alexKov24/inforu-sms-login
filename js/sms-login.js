jQuery(document).ready(function($) {
    const form = $('#sms-login-form');
    const phoneStep = $('#phone-step');
    const otpStep = $('#otp-step');
    const messageBox = $('#message-box');
    const phoneInput = $('#phone_number');
    const otpInput = $('#otp');

    // Initially disable OTP input
    otpInput.prop('disabled', true);

    form.on('submit', function(e) {
        e.preventDefault();
        const isPhoneStep = phoneStep.is(':visible');
        
        const data = {
            action: isPhoneStep ? 'verify_phone' : 'verify_otp',
            nonce: smsLoginAjax.nonce,
        };

        if (isPhoneStep) {
            data.phone = phoneInput.val();
        } else {
            data.otp = otpInput.val();
        }

        $.post(smsLoginAjax.ajaxurl, data, function(response) {
            if (response.success) {
                if (isPhoneStep) {
                    // Switch to OTP step
                    phoneStep.hide();
                    phoneInput.prop('required', false).prop('disabled', true);
                    
                    otpStep.show();
                    otpInput.prop('required', true).prop('disabled', false);
                    
                    messageBox.removeClass('error').text('OTP sent successfully');
                } else if (response.data.redirect_url) {
                    window.location.href = response.data.redirect_url;
                }
            } else {
                messageBox.addClass('error').text(response.data.message);
            }
        });
    });
});