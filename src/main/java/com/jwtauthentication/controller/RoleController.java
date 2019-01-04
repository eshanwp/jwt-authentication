package com.jwtauthentication.controller;

import com.jwtauthentication.dto.RoleDto;
import com.jwtauthentication.dto.RoleFormDto;
import com.jwtauthentication.dto.response.ApiResponse;
import com.jwtauthentication.service.RoleService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/role")
public class RoleController {

    // Define the log object for this class
    private final Logger log = Logger.getLogger(this.getClass());

    @Autowired
    private RoleService roleService;

    @Autowired
    private MessageSource messageSource;

    /**
     * @Des get all roles
     * @Return List<RoleDto>
     ***/
    @GetMapping(value = "/all" )
    public List<RoleDto> findAll(){

        log.info("method started. ");
        return roleService.findAll();
    }

    /**
     * @Des save role
     * @Param RoleFormDto
     * @Return resultcode/resultdescription in json format
     ***/
    @PostMapping(path = "/save", produces = "application/json")
    public ResponseEntity<?> saveOrUpdate(
            @RequestBody RoleFormDto roleFormDto
    ){

        log.info("method started. ");
        return roleSaveOrUpdate(roleFormDto, "save");
    }

    /**
     * @Des update role
     * @Param RoleFormDto
     * @Return resultcode/resultdescription in json format
     ***/
    @PutMapping(path = "/update", produces = "application/json")
    public ResponseEntity<?> update(
            @RequestBody RoleFormDto roleFormDto
    ){

        log.info("method started. ");
        return roleSaveOrUpdate(roleFormDto,"update");
    }

    private ResponseEntity<?> roleSaveOrUpdate(
            @RequestBody RoleFormDto roleFormDto,
            String result
    ) {

        log.info("method started. ");
        roleService.saveOrUpdate(roleFormDto);

        ApiResponse apiResponse = ApiResponse.getApiResponse("200", "role."+result, messageSource, log);
        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }
}
