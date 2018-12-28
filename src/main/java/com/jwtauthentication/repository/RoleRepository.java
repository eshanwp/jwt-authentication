package com.jwtauthentication.repository;

import java.util.Optional;

import com.jwtauthentication.entity.Role;
import com.jwtauthentication.entity.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);

    Role findByName(String name);
}
