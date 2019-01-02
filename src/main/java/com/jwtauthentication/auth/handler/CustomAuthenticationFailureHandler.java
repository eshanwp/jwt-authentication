package com.jwtauthentication.auth.handler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*********************************************************************************************************
 * We’re handling the situation when the user actually does get blocked for 24 hours – and we’re informing
 * the user that his IP is blocked because he exceeded the maximum allowed wrong authentication attempts:
 *********************************************************************************************************/

@Component("authenticationFailureHandler")
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private MessageSource messageSource;

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException exception) throws IOException, ServletException {
//        setDefaultFailureUrl("/login?error=true");

        super.onAuthenticationFailure(request, response, exception);

        String errorMessage = messageSource.getMessage("message.badCredentials", null, null);

        if (exception.getMessage().equalsIgnoreCase("User is disabled")) {
            errorMessage = messageSource.getMessage("auth.message.disabled", null, null);
        } else if (exception.getMessage().equalsIgnoreCase("User account has expired")) {
            errorMessage = messageSource.getMessage("auth.message.expired", null, null);
        } else if (exception.getMessage().equalsIgnoreCase("blocked")) {
            errorMessage = messageSource.getMessage("auth.message.blocked", null, null);
        }

        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, errorMessage);
    }
}
