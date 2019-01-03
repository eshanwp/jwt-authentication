package com.jwtauthentication.auth.listener;

import com.jwtauthentication.auth.event.OnRegistrationCompleteEvent;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.service.EmailService;
import com.jwtauthentication.service.implementation.IUserService;
import freemarker.template.TemplateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.UUID;

@Component
public class RegistrationListener implements ApplicationListener<OnRegistrationCompleteEvent> {
    @Autowired
    private IUserService service;

    @Autowired
    private MessageSource messageSource;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private Environment env;

    @Autowired
    private EmailService emailService;

    // API

    @Override
    public void onApplicationEvent(final OnRegistrationCompleteEvent event) {
        try {
            this.confirmRegistration(event);
        } catch (TemplateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private void confirmRegistration(final OnRegistrationCompleteEvent event) throws TemplateException, IOException, MessagingException {
        final User user = event.getUser();
        final String token = UUID.randomUUID().toString();
        service.createVerificationTokenForUser(user, token);

        emailService.constructResendVerificationTokenEmail(event, user, token);

    }


}
