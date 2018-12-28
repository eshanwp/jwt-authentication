package com.jwtauthentication.security.services;

import com.jwtauthentication.auth.service.LoginAttemptService;
import com.jwtauthentication.model.User;
import com.jwtauthentication.repository.RoleRepository;
import com.jwtauthentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.HttpServletRequest;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private HttpServletRequest request;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

//        User user = userRepository.findByUsername(username)
//                	.orElseThrow(() ->
//                        new UsernameNotFoundException("User Not Found with -> username or email : " + username)
//        );
//
//        return UserPrinciple.build(user);

        String ip = getClientIP();
        if (loginAttemptService.isBlocked(ip)) {
            throw new RuntimeException("Current user is blocked");
        }

        try {
            User user = userRepository.findByUsername(username);
            if (user == null) {
//                return new org.springframework.security.core.userdetails.User(
//                        " ", " ", true, true, true, true,
//                        getAuthorities(Arrays.asList(roleRepository.findByName("ROLE_USER"))));
            }

//            return new org.springframework.security.core.userdetails.User(
//                    user.getEmail(), user.getPassword(), true, true, true, true,
//                    getAuthorities(user.getRoles()));

            return UserPrinciple.build(user);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private String getClientIP() {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null){
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

//    private Collection<? extends GrantedAuthority> getAuthorities(
//            Collection<Role> roles) {
//
//        return getGrantedAuthorities(getPrivileges(roles));
//    }
}
