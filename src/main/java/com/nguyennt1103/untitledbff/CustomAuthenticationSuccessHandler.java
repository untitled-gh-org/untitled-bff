package com.nguyennt1103.untitledbff;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

import static com.nguyennt1103.untitledbff.BffConstants.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE;

@Slf4j
public class CustomAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy;
    private final String defaultRedirectUri;

    public CustomAuthenticationSuccessHandler(RedirectStrategy redirectStrategy, String postLoginSuccessUri) {
        this.redirectStrategy = redirectStrategy;
        this.defaultRedirectUri = Optional.ofNullable(postLoginSuccessUri)
                .orElse("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        HttpSession session = request.getSession(false);

        String redirectUri = Optional
                .ofNullable(session.getAttribute(POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE))
                .map(Objects::toString)
                .orElse(defaultRedirectUri);

        log.debug("Authentication success. Location: {}", redirectUri);

        redirectStrategy.sendRedirect(request, response, redirectUri);
    }
}
