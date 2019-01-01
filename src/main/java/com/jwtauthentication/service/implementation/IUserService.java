package com.jwtauthentication.service.implementation;

import com.jwtauthentication.auth.error.EmailExistsException;
import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.entity.VerificationToken;

public interface IUserService {

    User registerNewUserAccount(UserDto userDto)
            throws EmailExistsException;

    void createVerificationTokenForUser(User user, String token);

    VerificationToken getVerificationToken(String VerificationToken);

    void saveRegisteredUser(User user);

    VerificationToken generateNewVerificationToken(String token);

    User getUser(String verificationToken);

    User findUserByEmail(String email);

    void createPasswordResetTokenForUser(User user, String token);

}
