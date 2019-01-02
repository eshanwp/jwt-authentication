package com.jwtauthentication.auth.service.implementation;

public interface ISecurityUserService {

    String validatePasswordResetToken(long id, String token);

}
