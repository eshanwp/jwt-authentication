package com.jwtauthentication.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import com.jwtauthentication.auth.error.UserNotFoundException;
import com.jwtauthentication.auth.event.OnRegistrationCompleteEvent;
import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.entity.VerificationToken;
import com.jwtauthentication.service.implementation.IUserService;
import com.jwtauthentication.util.GenericResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.jwtauthentication.message.request.LoginForm;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.repository.RoleRepository;
import com.jwtauthentication.repository.UserRepository;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Locale;
import java.util.UUID;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    private IUserService userService;

    @Autowired
    private MessageSource messageSource;

    @Autowired
    ApplicationEventPublisher eventPublisher;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private Environment env;

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    @PostMapping("/signin")
    public GenericResponse authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return new GenericResponse(messageSource.getMessage("auth.message.logged", null, null));
    }

    //Using a Spring Event to Create the Token and Send the Verification Email and save data
    @PostMapping("/signup")
    public GenericResponse registerUser(@Valid @RequestBody UserDto userDto, final HttpServletRequest request) {
        User user = userService.registerNewUserAccount(userDto);

        try {
            String appUrl = getAppUrl(request);
            eventPublisher.publishEvent(new OnRegistrationCompleteEvent
                    (user, appUrl));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new GenericResponse(messageSource.getMessage("auth.message.user.created", null, null));
    }

    /*****************************************************************************************************
     *
     * The user will be redirected to an error page with the corresponding message if:
     * 1. The VerificationToken does not exist, for some reason or
     * 2. The VerificationToken has expired
     *
     * There are two opportunities for improvement in handling the VerificationToken checking and expiration scenarios:
     * We can use a Cron Job to check for token expiration in the background
     * We can give the user the opportunity to get a new token once it has expired
     *
     * The confirmRegistration controller will extract the value of the token parameter in the resulting GET
     * request and will use it to enable the User.
     *
     * ***************************************************************************************************/

    @GetMapping(value = "/registration-confirm")
    public GenericResponse confirmRegistration
    (final HttpServletRequest request, @RequestParam("token") String token, Model model) {

        Locale locale = request.getLocale();

        VerificationToken verificationToken = userService.getVerificationToken(token);
        if (verificationToken == null) {
            return new GenericResponse(messageSource.getMessage("auth.message.invalidToken", null, null));
        }

        User user = verificationToken.getUser();

        Calendar cal = Calendar.getInstance();

        if ((verificationToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0) {
            return new GenericResponse(messageSource.getMessage("auth.message.expired", null, null));
        }

        //If no errors are found, the user is enabled.
        user.setEnabled(true);
        userService.saveRegisteredUser(user);
        return new GenericResponse(messageSource.getMessage("auth.message.accountVerified", null, null));

    }

    //we’ll reset the existing token with a new expireDate. The, we’ll send the user a new email,
    //with the new link/token
    @GetMapping(value = "/resend-registration-token")
    public GenericResponse resendRegistrationToken(
            HttpServletRequest request, @RequestParam("token") String existingVerificationToken) {

        VerificationToken newToken = userService.generateNewVerificationToken(existingVerificationToken);

        User user = userService.getUser(newToken.getToken());

        String appUrl = getAppUrl(request);

        SimpleMailMessage email = constructResendVerificationTokenEmail(appUrl, newToken, user);
        mailSender.send(email);

        return new GenericResponse(
                messageSource.getMessage("auth.message.resendToken", null, null));
    }

    //we’ll reset the password with a new token. The, we’ll send the user a new email, with the new link/token
    @GetMapping(value = "/reset-password")
    public GenericResponse resetPassword(HttpServletRequest request, @RequestParam("email") String userEmail) {

        User user = userService.findUserByEmail(userEmail);

        if (user == null) {
            throw new UserNotFoundException();
        }
        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        mailSender.send(constructResetTokenEmail(getAppUrl(request), token, user));
        return new GenericResponse(
                messageSource.getMessage("auth.message.resetPasswordEmail", null,
                        null));
    }

    /**************************************************************
     * NON - API
     **************************************************************/

    private SimpleMailMessage constructResendVerificationTokenEmail
    (String contextPath, VerificationToken newToken, User user) {
        String confirmationUrl = contextPath + "/?token=" + newToken.getToken();
        String message = messageSource.getMessage("auth.message.resendToken", null, null);
        SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject("Resend Registration Token");
        email.setText(message + " rn" + confirmationUrl);
        email.setFrom(env.getProperty("support.email"));
        email.setTo(user.getEmail());
        return email;
    }

    //used to send an email with the reset token
    private SimpleMailMessage constructResetTokenEmail(
            String contextPath, String token, User user) {
        String url = contextPath + "/user/change-password?id=" +
                user.getId() + "&token=" + token;
        String message = messageSource.getMessage("message.resetPassword",
                null, null);
        return constructEmail("Reset Password", message + " \r\n" + url, user);
    }

    private SimpleMailMessage constructEmail(String subject, String body,
                                             User user) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject(subject);
        email.setText(body);
        email.setTo(user.getEmail());
        email.setFrom(env.getProperty("support.email"));
        return email;
    }

}
