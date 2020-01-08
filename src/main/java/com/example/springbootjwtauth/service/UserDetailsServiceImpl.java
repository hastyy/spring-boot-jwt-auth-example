package com.example.springbootjwtauth.service;

import com.example.springbootjwtauth.entity.User;
import com.example.springbootjwtauth.repository.UserRepository;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * This method will be called by the Authentication Provider selected by the Authentication Manager.
     * This is where we run the logic to find the user that matches the submitted credentials.
     *
     * @param email is the user identifier
     * @return UserDetails instance representing the Principal
     * @throws UsernameNotFoundException if the identified user is not found in the database
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findUserByEmail(email)
                .map(this::userEntityToUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("Could not find user"));
    }

    private UserDetails userEntityToUserDetails(User user) {
        UserDetailsImpl userDetails = new UserDetailsImpl();

        userDetails.setUsername(user.getEmail());
        userDetails.setPassword(user.getPassword());

        return userDetails;
    }

    /**
     * Custom implementation of UserDetails so we can build an instance to return to the calling
     * Authentication Provider.
     */
    @Data
    private static class UserDetailsImpl implements UserDetails {

        private String username;
        private String password;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Collections.emptySet();
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

    }

}
