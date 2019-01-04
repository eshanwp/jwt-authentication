package com.jwtauthentication.controller;

import com.jwtauthentication.dto.PrivilegeDto;
import com.jwtauthentication.service.PrivilegeService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/privilege")
public class PrivilegeController {

    // Define the log object for this class
    private final Logger log = Logger.getLogger(this.getClass());

    @Autowired
    private PrivilegeService privilegeService;

    /**
     * @Des get all privileges
     * @Return List<PrivilegeDto>
     ***/
    @GetMapping(path = "/all", produces = "application/json")
    public List<PrivilegeDto> findAll(){

        log.info("method started. ");
        return privilegeService.findAll();
    }
}
