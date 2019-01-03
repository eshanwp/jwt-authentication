package com.jwtauthentication.service.implementation;

import com.jwtauthentication.auth.event.OnRegistrationCompleteEvent;
import com.jwtauthentication.entity.User;
import freemarker.template.TemplateException;
import org.springframework.http.ResponseEntity;

import javax.mail.MessagingException;
import java.io.IOException;

public interface IEmailService {

    ResponseEntity<?> constructResendVerificationTokenEmail(final OnRegistrationCompleteEvent event, final User user, final String token) throws IOException, TemplateException, MessagingException;

    ResponseEntity<?> constructResetPasswordTokenEmail(final OnRegistrationCompleteEvent event, final User user, final String token) throws IOException, TemplateException, MessagingException;

}

