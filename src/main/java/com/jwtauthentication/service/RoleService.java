package com.jwtauthentication.service;

import com.jwtauthentication.converter.RoleConverter;
import com.jwtauthentication.converter.RoleFormConverter;
import com.jwtauthentication.dto.RoleDto;
import com.jwtauthentication.dto.RoleFormDto;
import com.jwtauthentication.entity.Role;
import com.jwtauthentication.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private RoleConverter roleConverter;

    @Autowired
    private RoleFormConverter roleFormConverter;

    public List<RoleDto> findAll() {
        return roleRepository.findAll().stream().map(roleConverter::entityToDto).collect(Collectors.toList());
    }

    public void saveOrUpdate(RoleFormDto roleFormDto) {
        Role role = roleFormConverter.dtoToEntity(roleFormDto);
        roleRepository.save(role);
    }
}
