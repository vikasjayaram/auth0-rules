function riskAssessment(user, context, callback) {
    const riskAssessment = context.riskAssessment;
    const enrolledFactors = user.multifactor || [];
    let shouldPromptMfa, shouldSendNotification;
    switch (riskAssessment.assessments.NewDevice.confidence) {
        case 'low':
        case 'medium':
            shouldPromptMfa = true;
            shouldSendNotification = true;
            break;
        case 'high':
            shouldPromptMfa = false;
            shouldSendNotification = false
            break;
        case 'neutral':
            // When this assessor has no useful information about the confidence, 
            // do not prompt MFA.
            shouldPromptMfa = false;
            shouldSendNotification = false;
            break;
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
        const template = '<html> <head> <style type="text/css"> .ExternalClass,.ExternalClass div,.ExternalClass font,.ExternalClass p,.ExternalClass span,.ExternalClass td,img{line-height:100%}#outlook a{padding:0}.ExternalClass,.ReadMsgBody{width:100%}a,blockquote,body,li,p,table,td{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}table,td{mso-table-lspace:0;mso-table-rspace:0}img{-ms-interpolation-mode:bicubic;border:0;height:auto;outline:0;text-decoration:none}table{border-collapse:collapse!important}#bodyCell,#bodyTable,body{height:100%!important;margin:0;padding:0;font-family:ProximaNova,sans-serif}#bodyCell{padding:20px}#bodyTable{width:600px}@font-face{font-family:ProximaNova;src:url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.eot);src:url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.eot?#iefix) format(\'embedded-opentype\'),url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-regular-webfont-webfont.woff) format(\'woff\');font-weight:400;font-style:normal}@font-face{font-family:ProximaNova;src:url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.eot);src:url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.eot?#iefix) format(\'embedded-opentype\'),url(https://cdn.auth0.com/fonts/proxima-nova/proximanova-semibold-webfont-webfont.woff) format(\'woff\');font-weight:600;font-style:normal}@media only screen and (max-width:480px){#bodyTable,body{width:100%!important}a,blockquote,body,li,p,table,td{-webkit-text-size-adjust:none!important}body{min-width:100%!important}#bodyTable{max-width:600px!important}#signIn{max-width:280px!important}} </style> </head> <body> <center> <table style="width: 600px;-webkit-text-size-adjust: 100%;-ms-text-size-adjust: 100%;mso-table-lspace: 0pt;mso-table-rspace: 0pt;margin: 0;padding: 0;font-family: "ProximaNova", sans-serif;border-collapse: collapse !important;height: 100% !important;" align="center" border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" id="bodyTable"> <tr> <td align="center" valign="top" id="bodyCell" style="-webkit-text-size-adjust: 100%;-ms-text-size-adjust: 100%;mso-table-lspace: 0pt;mso-table-rspace: 0pt;margin: 0;padding: 20px;font-family: "ProximaNova", sans-serif;height: 100% !important;"> <div class="main"> <p style="text-align: center;-webkit-text-size-adjust: 100%;-ms-text-size-adjust: 100%; margin-bottom: 30px;"> <img src="https://cdn.auth0.com/styleguide/2.0.9/lib/logos/img/badge.png" width="50" alt="Your logo goes here" style="-ms-interpolation-mode: bicubic;border: 0;height: auto;line-height: 100%;outline: none;text-decoration: none;"> </p> <h1>New device signed in to</h1> <br/> <h1>{{user.email}}</h1> <p>Your Account was just signed in to from a new device. You\'re getting this email to make sure that it was you. </p> <br> Thanks! </div> </td> </tr> </table> </center> </body></html>';
        engine
            .parseAndRender(template, { user: user })
            .then(function (renderedTemplate) {
                request.post({
                    url: 'https://api.sendgrid.com/api/mail.send.json',
                    headers: {
                        'Authorization': 'Bearer ' + configuration.SENDGRID_API_KEY
                    },
                    form: {
                        'to': user.email,
                        'subject': 'Login Alert',
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
