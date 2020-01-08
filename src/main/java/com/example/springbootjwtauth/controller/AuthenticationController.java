package com.example.springbootjwtauth.controller;

import com.example.springbootjwtauth.dto.AuthenticationToken;
import com.example.springbootjwtauth.dto.UserCredentials;
import com.example.springbootjwtauth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(AuthenticationController.BASE_URL)
public class AuthenticationController {

    public static final String BASE_URL = "/authenticate";

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    /**
     * This endpoint is not protected by an authorization guard.
     * This endpoint is equivalent to the default /login endpoint that Spring Security provides, but we cut the html
     * form from the process and manually wire the internal components ourselves.
     *
     * First, we create an Authentication object from the credentials.
     * We use an instance of UsernamePasswordAuthenticationToken because it defines the username and password
     * authentication strategy.
     *
     * Keep in mind that Authentication represents a message container for the internal authentication components to
     * communicate between them.
     *
     * We pass this instance to the Authentication Manager, which will look at its type (strategy) and will ask
     * the Authentication Providers if any supports() UsernamePasswordAuthentication.
     *
     * Finding one Authentication Provider that supports() it, the Authentication Manager will call the Provider's
     * authenticate method with the same object.
     *
     * The Authentication Provider will take the user identifier (internally, these components always refer to it as
     * username) from the object and will pass it to the UserDetailsService, calling loadUserByUserName().
     *
     * Here, we are providing our own implementation as the Bean for UserDetailsService. It will take the user
     * identifier and will try to find such user in the repository (in our case it might be a SQL database, but it
     * could be anything from an in-memory structure, to a file or another service).
     *
     * If such user is found, it will be mapped into a UserDetails instance (we also provide our own here) and given
     * back to the Authentication Provider, which will wrap it in a new Authentication container, return it to the
     * Authentication Manager and the Authentication Manager will return it back to us.
     *
     * We can now say that we've established the Principal.
     *
     * Given the Principal (which is basically the correct technical name for authenticated user account), we can
     * generate a JWT containing the information we need to authorize it in further requests.
     *
     * We finally return this token to the client.
     *
     * @param userCredentials are the submitted credentials
     * @return the JWT to be used to authorize subsequent requests
     * @throws AuthenticationException when we are not able to authenticate the user, i.e. the credentials do not match
     */
    @PostMapping
    public AuthenticationToken authenticate(@RequestBody UserCredentials userCredentials)
            throws AuthenticationException {

        Authentication credentials = wrapCredentials(userCredentials);
        Authentication principal = authenticationManager.authenticate(credentials);

        String jwt = jwtService.generateToken(principal);

        return AuthenticationToken.of(jwt);
    }

    private Authentication wrapCredentials(UserCredentials credentials) {
        return new UsernamePasswordAuthenticationToken(credentials.getEmail(), credentials.getPassword());
    }
}
