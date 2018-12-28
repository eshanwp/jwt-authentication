package com.jwtauthentication.service;

import com.jwtauthentication.auth.error.EmailExistsException;
import com.jwtauthentication.converter.UserConverter;
import com.jwtauthentication.dto.UserDto;
import com.jwtauthentication.entity.User;
import com.jwtauthentication.repository.RoleRepository;
import com.jwtauthentication.repository.UserRepository;
import com.jwtauthentication.service.implementation.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class UserService implements IUserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserConverter userConverter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerNewUserAccount(UserDto userDto) throws EmailExistsException {
        if (emailExist(userDto.getEmail())) {
            throw new EmailExistsException(
                    "There is an account with that email address:  " + userDto.getEmail()
            );
        }

        User user = userConverter.dtoToEntity(userDto);
        user.setName(userDto.getName());
        user.setUserName(userDto.getUserName());
        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setEnabled(true);
        user.setRoles(Arrays.asList(roleRepository.findByName("ROLE_USER")));

        return userRepository.save(user);
    }

    //Checks for Duplicate Emails
    private boolean emailExist(String email) {
        User user = userRepository.findByEmail(email);
        if (user != null) {
            return true;
        }
        return false;
    }

}
