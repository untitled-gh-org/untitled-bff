package com.nguyennt1103.untitledbff;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public interface AuthoritiesConverter extends Converter<Map<String, Object>, Collection<GrantedAuthority>> {

    @NonNull
    @Override
    Collection<GrantedAuthority> convert(@NonNull Map<String, Object> source);
}
