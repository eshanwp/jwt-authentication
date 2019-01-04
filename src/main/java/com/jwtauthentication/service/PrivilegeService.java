package com.jwtauthentication.service;

import com.jwtauthentication.converter.PrivilegeConverter;
import com.jwtauthentication.dto.PrivilegeDto;
import com.jwtauthentication.repository.PrivilegeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class PrivilegeService {

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private PrivilegeConverter privilegeConverter;

    public List<PrivilegeDto> findAll() {
        return privilegeRepository.findAll().stream().map(privilegeConverter::entityToDto).collect(Collectors.toList());
    }
}
