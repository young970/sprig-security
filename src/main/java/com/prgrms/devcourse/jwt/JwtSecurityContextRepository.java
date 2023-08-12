package com.prgrms.devcourse.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;

import static io.micrometer.common.util.StringUtils.isNotEmpty;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

public class JwtSecurityContextRepository implements SecurityContextRepository {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private final String headerKey;

  private final Jwt jwt;

  public JwtSecurityContextRepository(String headerKey, Jwt jwt) {
    this.headerKey = headerKey;
    this.jwt = jwt;
  }

  @Override
  public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
    HttpServletRequest request = requestResponseHolder.getRequest();
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    JwtAuthenticationToken authentication = authenticate(request);
    if (authentication != null) {
      context.setAuthentication(authentication);
    }
    return context;
  }

  @Override
  public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    /*no-op*/
  }

  @Override
  public boolean containsContext(HttpServletRequest request) {
    JwtAuthenticationToken authentication = authenticate(request);
    return authentication != null;
  }

  private JwtAuthenticationToken authenticate(HttpServletRequest request) {
    String token = getToken(request);
    if (isNotEmpty(token)) {
      try {
        Jwt.Claims claims = jwt.verify(token);
        log.debug("Jwt parse result: {}", claims);

        String username = claims.username;
        List<GrantedAuthority> authorities = getAuthorities(claims);
        if (isNotEmpty(username) && authorities.size() > 0) {
          JwtAuthenticationToken authentication
            = new JwtAuthenticationToken(new JwtAuthentication(token, username), null, authorities);
          authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
          return authentication;
        }
      } catch (Exception e) {
        log.warn("Jwt processing failed: {}", e.getMessage());
      }
    }
    return null;
  }

  private String getToken(HttpServletRequest request) {
    String token = request.getHeader(headerKey);
    if (isNotEmpty(token)) {
      log.debug("Jwt authorization api detected: {}", token);
      try {
        return URLDecoder.decode(token, "UTF-8");
      } catch (UnsupportedEncodingException e) {
        log.error(e.getMessage(), e);
      }
    }
    return null;
  }

  private List<GrantedAuthority> getAuthorities(Jwt.Claims claims) {
    String[] roles = claims.roles;
    return (roles == null || roles.length == 0)
      ? emptyList()
      : Arrays.stream(roles).map(SimpleGrantedAuthority::new).collect(toList());
  }

}