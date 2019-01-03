package com.jwtauthentication.service;

import com.jwtauthentication.auth.event.OnRegistrationCompleteEvent;
import com.jwtauthentication.dto.response.ApiResponse;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.service.implementation.IEmailService;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.jwtauthentication.dto.response.ApiResponse.getApiResponse;

@Service
public class EmailService implements IEmailService {

    // Define the log object for this class
    private final Logger log = Logger.getLogger(this.getClass());

    @Autowired
    private JavaMailSender sender;

    @Autowired
    private Configuration freemarkerConfig;

    @Autowired
    private MessageSource messageSource;

    @Override
    public ResponseEntity<?> constructResendVerificationTokenEmail(OnRegistrationCompleteEvent event, User user, String token) throws IOException, TemplateException, MessagingException {
        log.info("constructResendVerificationTokenEmail method started. ");

        final String confirmationUrl = event.getAppUrl() + "/api/auth/registration-confirm?token=" + token;

        MimeMessage message = sender.createMimeMessage();

        MimeMessageHelper helper = new MimeMessageHelper(message);

        Map<String, Object> model = new HashMap<>();
        model.put("confirmationUrl", confirmationUrl);
        model.put("user", user.getName());

        // set loading location to src/main/resources
        // You may want to use a subfolder such as /templates here
        freemarkerConfig.setClassForTemplateLoading(this.getClass(), "/email_template");

        Template t = freemarkerConfig.getTemplate("welcome.ftl");
        String text = FreeMarkerTemplateUtils.processTemplateIntoString(t, model);

        helper.setTo(user.getEmail());
        helper.setText(text, true); // set to html
        helper.setSubject("Registration Confirmation");

        sender.send(message);

        ApiResponse apiResponse = getApiResponse("200", "auth.message.resendToken", messageSource, log);
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }

    @Override
    public ResponseEntity<?> constructResetPasswordTokenEmail(OnRegistrationCompleteEvent event, User user, String token) throws IOException, TemplateException, MessagingException {

        log.info("constructResetPasswordTokenEmail method started. ");

        final String confirmationUrl = event.getAppUrl() + "/api/auth/change-password?id=" + user.getId() + "&token=" + token;

        MimeMessage message = sender.createMimeMessage();

        MimeMessageHelper helper = new MimeMessageHelper(message);

        Map<String, Object> model = new HashMap<>();
        model.put("url", confirmationUrl);
        model.put("userName", user.getName());

        freemarkerConfig.setClassForTemplateLoading(this.getClass(), "/email_template");

        Template t = freemarkerConfig.getTemplate("password_reset.ftl");
        String text = FreeMarkerTemplateUtils.processTemplateIntoString(t, model);

        helper.setTo(user.getEmail());
        helper.setText(text, true); // set to html
        helper.setSubject("Reset Password");

        sender.send(message);

        ApiResponse apiResponse = getApiResponse("200", "auth.message.resetPasswordEmail", messageSource, log);
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }
}
