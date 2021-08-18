function riskAssessment(user, context, callback) {
    /**
     * This rule checks for risK assessment and sends security notification 
     * to the end user if the user is logging in from a new device.
     */
    const riskAssessment = context.riskAssessment;
    const enrolledFactors = user.multifactor || [];
    let shouldPromptMfa = false, shouldSendNotification = false;
    if (riskAssessment && riskAssessment.assessments) {
        switch (riskAssessment.assessments.NewDevice.confidence) {
            case 'low':
            case 'medium':
                shouldPromptMfa = true;
                shouldSendNotification = true;
                break;
            case 'high':
                shouldPromptMfa = false;
                shouldSendNotification = false;
                break;
            case 'neutral':
                // When this assessor has no useful information about the confidence, 
                // do not prompt MFA.
                shouldPromptMfa = false;
                shouldSendNotification = false;
                break;
        }
    }

    if (shouldSendNotification) {
        sendSecurityNotification();
    }

    if (shouldPromptMfa && enrolledFactors.length > 0) {
        context.multifactor = {
            provider: 'any',
            // ensure that we will prompt MFA, even if the end-user has selected to 
            // remember the browser.
            allowRememberBrowser: false
        };
    } else {
        // Skip MFA
        context.multifactor = {
            provider: 'none'
        };
    }
    function sendSecurityNotification() {
        const request = require('request');
        var Liquid = require("liquid-node");
        var engine = new Liquid.Engine();
        // Rebrand this template
        const template = '<html><head> <style type="text/css"> .ExternalClass, .ExternalClass div, .ExternalClass font, .ExternalClass p, .ExternalClass span, .ExternalClass td, img { line-height: 100% } #outlook a { padding: 0 } .ExternalClass, .ReadMsgBody { width: 100% } a, blockquote, body, li, p, table, td { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100% } table, td { mso-table-lspace: 0; mso-table-rspace: 0 } img { -ms-interpolation-mode: bicubic; border: 0; height: auto; outline: 0; text-decoration: none } table { border-collapse: collapse !important } #bodyCell, #bodyTable, body { height: 100% !important; margin: 0; padding: 0; font-family: ProximaNova, sans-serif } #bodyCell { padding: 20px } #bodyTable { width: 600px } @font-face { font-family: ProximaNova; src: url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.eot); src: url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.eot?#iefix) format(\'embedded-opentype\'), url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.woff) format(\'woff\'); font-weight: 400; font-style: normal } @font-face { font-family: ProximaNova; src: url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.eot); src: url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.eot?#iefix) format(\'embedded-opentype\'), url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.woff) format(\'woff\'); font-weight: 600; font-style: normal } @media only screen and (max-width:480px) { #bodyTable, body { width: 100% !important } a, blockquote, body, li, p, table, td { -webkit-text-size-adjust: none !important } body { min-width: 100% !important } #bodyTable { max-width: 600px !important } #signIn { max-width: 280px !important } } </style></head><body> <p>&nbsp;</p> <center> <table id="bodyTable" style="width: 600px; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; mso-table-lspace: 0pt; mso-table-rspace: 0pt; margin: 0; padding: 0;" border="0" width="100%" cellspacing="0" cellpadding="0" align="center"> <tbody> <tr> <td id="bodyCell" style="-webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; mso-table-lspace: 0pt; mso-table-rspace: 0pt; margin: 0; padding: 20px;" align="center" valign="top"> <div class="main"> <p style="text-align: center; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; margin-bottom: 30px;"> <img style="-ms-interpolation-mode: bicubic; border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none;" src="https://cdn.auth0.com/styleguide/2.0.9/lib/logos/img/badge.png" alt="Your logo goes here" width="50" /></p> <h1>New device signed in to</h1> <br /> <h1>{{user.email}}</h1> <table style="border-collapse: collapse; width: 100%; height: 72px;" border="1"> <tbody> <tr style="height: 18px;"> <td style="width: 50%; height: 18px;">IP Address</td> <td style="width: 50%; height: 18px;">{{context.request.ip}}</td> </tr> <tr style="height: 18px;"> <td style="width: 50%; height: 18px;">User Agent</td> <td style="width: 50%; height: 18px;">{{context.request.userAgent}}</td> </tr> <tr style="height: 18px;"> <td style="width: 50%; height: 18px;">Geo Location Country</td> <td style="width: 50%; height: 18px;">{{context.request.geoip.country_name}} </td> </tr> <tr style="height: 18px;"> <td style="width: 50%; height: 18px;">Geo Location City</td> <td style="width: 50%; height: 18px;">{{context.request.geoip.city_name}}</td> </tr> </tbody> </table> <p>Your Account was just signed in to from a new device. You\'re getting this email to make sure that it was you. If this is not you please reset your password.</p> <br />Thanks! </div> </td> </tr> </tbody> </table> </center></body></html>';
        engine
            .parseAndRender(template, { user: user, context: context })
            .then(function (renderedTemplate) {
                request.post({
                    url: 'https://api.sendgrid.com/api/mail.send.json',
                    headers: {
                        'Authorization': 'Bearer ' + configuration.SENDGRID_API_KEY
                    },
                    form: {
                        'to': user.email,
                        'subject': 'Security Alert',
                        'from': 'no-reply@skymomentum.com.au',
                        'html': renderedTemplate
                    }
                }, function (error, response, body) {
                    console.log(error);
                    console.log(body);
                });
            })
            .catch(error => callback(error));
    }
    callback(null, user, context);
}
