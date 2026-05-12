package com.nguyennt1103.untitledbff;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.*;

@RequiredArgsConstructor
public class CustomGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

    private final AuthoritiesConverter authoritiesConverter;

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mapped = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                Collection<GrantedAuthority> roles = authoritiesConverter
                        .convert(oidcUserAuthority.getIdToken().getClaims());

                roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .forEach(mapped::add);
            }
        }

        return mapped;
    }
}
