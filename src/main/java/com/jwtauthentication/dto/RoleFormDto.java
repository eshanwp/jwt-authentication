package com.jwtauthentication.dto;

import java.util.ArrayList;
import java.util.Collection;

public class RoleFormDto {

    private Long id;

    private String name;

    //One to Many
    private Collection<PrivilegeDto> privilegeDtos = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Collection<PrivilegeDto> getPrivilegeDtos() {
        return privilegeDtos;
    }

    public void setPrivilegeDtos(Collection<PrivilegeDto> privilegeDtos) {
        this.privilegeDtos = privilegeDtos;
    }
}
