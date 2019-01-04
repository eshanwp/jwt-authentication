package com.jwtauthentication.converter;

import com.jwtauthentication.dto.RoleDto;
import com.jwtauthentication.entity.Role;
import org.springframework.stereotype.Component;

@Component
public class RoleConverter {
    public RoleDto entityToDto(Role role) {

        RoleDto roleDto = new RoleDto();
        roleDto.setId(role.getId());
        roleDto.setName(role.getName());
        return roleDto;
    }

}
