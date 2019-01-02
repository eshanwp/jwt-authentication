package com.jwtauthentication.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import com.jwtauthentication.auth.error.InvalidOldPasswordException;
import com.jwtauthentication.auth.event.OnRegistrationCompleteEvent;
import com.jwtauthentication.auth.service.implementation.ISecurityUserService;
import com.jwtauthentication.dto.PasswordDto;
import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.dto.response.ApiResponse;
import com.jwtauthentication.entity.VerificationToken;
import com.jwtauthentication.service.implementation.IUserService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.jwtauthentication.message.request.LoginForm;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.repository.RoleRepository;
import com.jwtauthentication.repository.UserRepository;

import java.util.Calendar;
import java.util.UUID;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    // Define the log object for this class
    private final Logger log = Logger.getLogger(this.getClass());

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

    @Autowired
    private ISecurityUserService securityUserService;

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    /**
     * @Des User sign in
     * @Param LoginForm data
     * @Return resultcode/resultdescription in json format
     * */
    @PostMapping(path = "/signin", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> authenticateUser(
            @Valid @RequestBody LoginForm loginRequest,
            final HttpServletRequest request
    ) {

        log.info("authenticateUser method started. ");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        ApiResponse apiResponse = apiResponse("200", "auth.message.logged");

        log.info(((User) authentication.getPrincipal()).getUserName() + " has been successfully logged");

        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }

    /**
     * @Des Using a Spring Event to Create the Token and Send the Verification Email and save data
     * @Param UserDto data
     * @Param HttpServletRequest
     * @Return resultcode/resultdescription in json format
     * */
    @PostMapping(path = "/signup", produces = "application/json")
    public ResponseEntity<?> registerUser(
            @Valid @RequestBody UserDto userDto,
            final HttpServletRequest request
    ) {
        log.info("registerUser method started. ");

        User user = userService.registerNewUserAccount(userDto);

        try {
            String appUrl = getAppUrl(request);
            eventPublisher.publishEvent(new OnRegistrationCompleteEvent
                    (user, appUrl));
        } catch (Exception e) {

            ApiResponse apiResponse = apiResponse("400", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);
        }

        ApiResponse apiResponse = apiResponse("200", "auth.message.logged");

        log.info("User " + user.getUserName() + " has been successfully registered");

        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }

    /**
     * @Des
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
     * @Param HttpServletRequest
     * @Param token
     * @Return resultcode/resultdescription in json format
     **/

    @GetMapping(value = "/registration-confirm", produces = "application/json")
    public ResponseEntity<?> confirmRegistration(
            final HttpServletRequest request,
            @RequestParam("token") String token
    ) {

        log.info("confirmRegistration method started. ");

        VerificationToken verificationToken = userService.getVerificationToken(token);
        if (verificationToken == null) {

            ApiResponse apiResponse = apiResponse("404", "auth.message.invalidToken");

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiResponse);
        }

        User user = verificationToken.getUser();

        Calendar cal = Calendar.getInstance();

        if ((verificationToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0) {

            ApiResponse apiResponse = apiResponse("200", "auth.message.expired");
            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        }

        //If no errors are found, the user is enabled.
        user.setEnabled(true);

        log.info("User is enabled");

        userService.saveRegisteredUser(user);

        ApiResponse apiResponse = apiResponse("200", "auth.message.accountVerified");
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }

    /**
     * @Des we’ll reset the existing token with a new expireDate. The, we’ll send the user a new email,with the new link/token
     * @Param token
     * @Param HttpServletRequest
     * @Return resultcode/resultdescription in json format
     ***/

    @GetMapping(value = "/resend-registration-token", produces = "application/json")
    public ResponseEntity<?> resendRegistrationToken(
            HttpServletRequest request,
            @RequestParam("token") String existingVerificationToken
    ) {

        log.info("resendRegistrationToken method started. ");

        VerificationToken newToken = userService.generateNewVerificationToken(existingVerificationToken);

        User user = userService.getUser(newToken.getToken());

        String appUrl = getAppUrl(request);

        SimpleMailMessage email = constructResendVerificationTokenEmail(appUrl, newToken, user);
        mailSender.send(email);

        ApiResponse apiResponse = apiResponse("200", "auth.message.resendToken");
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }

    /**
     * @Des we’ll reset the password with a new token. The, we’ll send the user a new email, with the new link/token
     * @Param email
     * @Param HttpServletRequest
     * @Return resultcode/resultdescription in json format
     **/
    @GetMapping(value = "/reset-password", produces = "application/json")
    public ResponseEntity<?> resetPassword(
            HttpServletRequest request,
            @RequestParam("email") String userEmail
    ) {
        log.info("resetPassword method started. ");

        User user = userService.findUserByEmail(userEmail);

        if (user == null) {
            ApiResponse apiResponse = apiResponse("404", "auth.message.userNotFound");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiResponse);
        }

        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        mailSender.send(constructResetTokenEmail(getAppUrl(request), token, user));

        ApiResponse apiResponse = apiResponse("200", "auth.message.resetPasswordEmail");
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }

    /**
     * @Des check the token is valid or not
     * @Param id
     * @Param token
     * @Return resultcode/resultdescription in json format
     **/
    @GetMapping(value = "/change-password", produces = "application/json")
    public ResponseEntity<?> showChangePasswordPage(
            @RequestParam("id") long id,
            @RequestParam("token") String token
    ) {

        log.info("showChangePasswordPage method started. ");

        String result = securityUserService.validatePasswordResetToken(id, token);
        if (result != null) {
            ApiResponse apiResponse = apiResponse("404", "auth.message." + result);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiResponse);
        }
        //At this point, the user sees the simple Password Reset page – where the only
        //possible option is to provide a new password
        ApiResponse apiResponse = apiResponse("200", "auth.message.validToken");
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }

    /**
     * @Des Notice how the method is secured via the @PreAuthorize annotation, since it should only accessible to logged in users.
     * @Param PasswordDto data
     * @Return resultcode/resultdescription in json format
     **/
    @PostMapping(value = "/update-password", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> changeUserPassword(
           @RequestBody PasswordDto passwordDto
    ) {

        log.info("changeUserPassword method started. ");

        final User user = userService.findUserByEmail(passwordDto.getEmail());

        if (!userService.checkIfValidOldPassword(user, passwordDto.getOldPassword())) {
            throw new InvalidOldPasswordException();
        }
        userService.changeUserPassword(user, passwordDto.getNewPassword());

        ApiResponse apiResponse = apiResponse("200", "auth.message.updatePasswordSuc");
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

    }

    /**************************************************************
     * NON - API
     **************************************************************/

    private ApiResponse apiResponse(String code, String des){

        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setResultCode(code);

        String description = messageSource.getMessage(des, null, null);
        apiResponse.setResultDescription(description);

        log.info(description);

        return apiResponse;

    }

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
    private SimpleMailMessage constructResetTokenEmail(String contextPath, String token, User user) {
        String url = contextPath + "/change-password?id=" + user.getId() + "&token=" + token;
        String message = messageSource.getMessage("auth.message.resetPasswordEmail", null, null);
        return constructEmail("Reset Password", message + " \r\n" + url, user);
    }

    private SimpleMailMessage constructEmail(String subject, String body, User user) {
        SimpleMailMessage email = new SimpleMailMessage();
        email.setSubject(subject);
        email.setText(body);
        email.setTo(user.getEmail());
        email.setFrom(env.getProperty("support.email"));
        return email;
    }

}
