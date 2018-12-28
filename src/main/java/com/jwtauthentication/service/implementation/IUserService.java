package com.jwtauthentication.service.implementation;

import com.jwtauthentication.auth.error.EmailExistsException;
import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.entity.User;

public interface IUserService {

    User registerNewUserAccount(UserDto userDto)
            throws EmailExistsException;

}
