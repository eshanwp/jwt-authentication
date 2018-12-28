package com.jwtauthentication.auth.handler;

import org.springframework.security.core.AuthenticationException;
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

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException exception) throws IOException, ServletException {
//        setDefaultFailureUrl("/login?error=true");

        super.onAuthenticationFailure(request, response, exception);

        if (exception.getMessage().equalsIgnoreCase("User is disabled")) {
            System.out.println("User is disabled");
        } else if (exception.getMessage().equalsIgnoreCase("User account has expired")) {
            System.out.println("User account has expired");
        } else if (exception.getMessage().equalsIgnoreCase("blocked")) {
            System.out.println("user is blocked");
        }

//        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, errorMessage);
    }
}
