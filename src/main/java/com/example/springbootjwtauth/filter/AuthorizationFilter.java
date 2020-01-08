package com.example.springbootjwtauth.filter;

import com.example.springbootjwtauth.controller.AuthenticationController;
import com.example.springbootjwtauth.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.util.StringUtils.hasText;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    public static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * This will run for each request, before it hits the target endpoint.
     * Our job here is trying to authorize the user based on the passed JWT.
     *
     * This is basically replacing the default Spring Security mechanism to authorize the user based on the session.
     * The difference is that now, instead of a 'reference to a ticket' (session) we have a 'copy of the exact ticket'
     * (JWT). The big difference is that sessions bound us to a single service instance because we are passing it the
     * reference to the information that identifies the user, i.e. that service instance is keeping it in memory.
     *
     * On the other hand, using JWTs we are passing the actual information and in that way we can be served by different
     * service instances.
     *
     * To be authorized we have to passed the previously retrieved JWT in the 'Authorization' header. The token should
     * also be prefixed with 'Bearer '.
     *
     * First, we attempt to extract the JWT from the header. If it's not present, it's invalid, or if doesn't follow
     * the required pattern, we stop our flow. Otherwise, we check to see if there's not already an established
     * Principal for the given request.
     *
     * In such condition, we take use the identifier in the JWT to confirm that such user (still) exists in the
     * system. If we find the user, we basically mimic what Spring Security does when it establishes a session:
     *
     * 1. Create the Authentication wrapper that represents the Principal
     * 2. Put it in the Security Context as the authenticated Principal
     *
     * Note that this is basically the part that is missing in the /authenticate endpoint to complete the full
     * session establishment that Spring Security performs using the defaults configurations. By validating the JWT
     * and establishing the Principal, we resume the authentication state we have when we return from the authentication
     * routine. Now we simply set the principal in the Security Context and basically establish a session.
     *
     * The big difference is that our session creation policy here is stateless, i.e. because we are not really
     * establishing a (lasting) session, we have to do this process for each request to be able to authorize the user.
     *
     * Bottom line: Because our sessions are stateless (i.e. we have no sessions) we have to set the context for each
     * request.
     *
     * If we fail to set the Principal in the Security Context, the request won't be authorized later on (by another
     * filter).
     *
     * Lastly, we have to continue the filter chain.
     *
     * @param request - http request
     * @param response - http response
     * @param filterChain - following filters in the request chain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTHORIZATION_HEADER_KEY);

        try {
            String jwt = extractJwtFromHeader(header);
            String username = jwtService.extractUsername(jwt);  // fails for invalid tokens

            Authentication principal = SecurityContextHolder.getContext().getAuthentication();

            if (!jwtService.isTokenExpired(jwt) && principal == null) {

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (userDetails.getUsername().equals(username)) {
                    setRequestSession(request, userDetails);
                }
            }
        } catch (Exception ex) {
            log.warn("Failed to authorize request with Authentication header: {}", header);
            log.debug(ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwtFromHeader(String header) {
        return hasText(header) && header.startsWith(AUTHORIZATION_HEADER_PREFIX)
                ? header.substring(AUTHORIZATION_HEADER_PREFIX.length())
                : null;
    }

    private void setRequestSession(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

    /**
     * Because we are extending OncePerRequestFilter, the filter will run for each request, even to unprotected routes
     * like /authenticate. That can cause some problems so we have to bypass the necessary endpoints here.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return new AntPathMatcher().match(AuthenticationController.BASE_URL, request.getServletPath());
    }

}
