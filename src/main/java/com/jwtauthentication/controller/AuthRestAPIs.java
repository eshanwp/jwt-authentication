package com.jwtauthentication.controller;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.service.implementation.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwtauthentication.message.request.LoginForm;
import com.jwtauthentication.message.request.SignUpForm;
import com.jwtauthentication.message.response.JwtResponse;
import com.jwtauthentication.entity.Role;
import com.jwtauthentication.entity.RoleName;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.repository.RoleRepository;
import com.jwtauthentication.repository.UserRepository;
import com.jwtauthentication.security.jwt.JwtProvider;

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
    JwtProvider jwtProvider;

    @Autowired
    private IUserService userService;

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserDto userDto, final HttpServletRequest request) {
//        if(userRepository.existsByUserName(signUpRequest.getUsername())) {
//            return new ResponseEntity<String>("Fail -> Username is already taken!",
//                    HttpStatus.BAD_REQUEST);
//        }
//
//        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
//            return new ResponseEntity<String>("Fail -> Email is already in use!",
//                    HttpStatus.BAD_REQUEST);
//        }
//
//        // Creating user's account
//        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
//                signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));
//
//        Set<String> strRoles = signUpRequest.getRole();
//        Set<Role> roles = new HashSet<>();
//
//        strRoles.forEach(role -> {
//        	switch(role) {
//	    		case "admin":
//	    			Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	    			roles.add(adminRole);
//
//	    			break;
//	    		case "pm":
//	            	Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	            	roles.add(pmRole);
//
//	    			break;
//	    		default:
//	        		Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	        		roles.add(userRole);
//        	}
//        });
//
//        user.setRoles(roles);
//        userRepository.save(user);

        System.out.println(userDto.toString());

        User user =  userService.registerNewUserAccount(userDto);

        try {

            String appUrl = getAppUrl(request);

//            eventPublisher.publishEvent(new OnRegistrationCompleteEvent
//                    (user, request.getLocale(), appUrl));

        }catch (Exception e){
            e.printStackTrace();
        }

        return ResponseEntity.ok().body("User has been successfully created");
    }
}
