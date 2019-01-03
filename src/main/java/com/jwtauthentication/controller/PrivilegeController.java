package com.jwtauthentication.controller;

import com.jwtauthentication.dto.PrivilegeDto;
import com.jwtauthentication.service.PrivilegeServe;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/privilege")
public class PrivilegeController {

    @Autowired
    private PrivilegeServe privilegeServe;

    @GetMapping(path = "/all")
    public PrivilegeDto findAll(){

    }
}
