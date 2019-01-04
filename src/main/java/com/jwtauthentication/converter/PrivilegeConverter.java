package com.jwtauthentication.converter;

import com.jwtauthentication.dto.PrivilegeDto;
import com.jwtauthentication.entity.Privilege;
import org.springframework.stereotype.Component;

@Component
public class PrivilegeConverter {


    public PrivilegeDto entityToDto(Privilege privilege) {
        PrivilegeDto privilegeDto = new PrivilegeDto();
        privilegeDto.setId(privilege.getId());
        privilegeDto.setName(privilege.getName());

        return privilegeDto;
    }

    public static Privilege dtoToEntity(PrivilegeDto privilegeDto) {
        Privilege privilege = new Privilege();
        privilege.setId(privilegeDto.getId());
        return privilege;
    }
}
