package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.jwt.JwtAuthenticationFilter;
import com.prgrms.devcourse.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.prgrms.devcourse.oauth2.OAuth2AuthenticationSuccessHandler;
import com.prgrms.devcourse.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;


@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private final JwtConfigure jwtConfigure;

  public WebSecurityConfigure(JwtConfigure jwtConfigure) {
    this.jwtConfigure = jwtConfigure;
  }

  @Bean
  WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers(antMatcher("/assets/**"), antMatcher("/h2-console/**"));
  }

  @Bean
  public Jwt jwt() {
    return new Jwt(
            jwtConfigure.getIssuer(),
            jwtConfigure.getClientSecret(),
            jwtConfigure.getExpirySeconds()
    );
  }

  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt());
  }

  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(
          JdbcOperations jdbcOperations,
          ClientRegistrationRepository clientRegistrationRepository
  ) {
    return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
  }

  @Bean
  public OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
  }

  @Bean
  HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository() {
    return new HttpCookieOAuth2AuthorizationRequestRepository();
  }

  @Bean
  public OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(Jwt jwt, UserService userService) {
    return new OAuth2AuthenticationSuccessHandler(jwt, userService);
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    ApplicationContext context = http.getSharedObject(ApplicationContext.class);

    http
            /**
             * 권한 추가
             */
            .authorizeHttpRequests((authorize) -> authorize
                    .requestMatchers(antMatcher("/assets/**"), antMatcher("/h2-console/**"))
                    .permitAll()
                    .requestMatchers(antMatcher("/api/user/me")).access(allOf(hasRole("USER"),hasRole("ADMIN"))) //hasAnyRole("USER", "ADMIN")
                    .anyRequest().permitAll())
            .csrf()
            .disable()
            .headers()
            .disable()
            /**
             * 로그인 추가
             */
            .formLogin()
            .disable()
            /**
             * 로그아웃 추가
             */
            .logout()
            .disable()
            /**
             * 아이디 비번 쿠키 기반 기억하기
             */
            .rememberMe()// 쿠키 기반
            .disable()
            /**
             * 익명 사용자 추가
             * AnonymousAuthenticationFilter
             */
            .anonymous((anonymous) -> anonymous
                    .principal("thisIsAnonymousUser")
                    .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
            )
            .exceptionHandling((exceptionHandling) -> exceptionHandling
                    .accessDeniedHandler(accessDeniedHandler())
            )
            .sessionManagement((sessionManagement -> sessionManagement
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            ))

            .oauth2Login((oauth2Login) -> oauth2Login
                    .authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint
                            .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository())
                    )
                    .successHandler(oauth2AuthenticationSuccessHandler(jwt(), context.getBean(UserService.class)))
                    .authorizedClientRepository(context.getBean(AuthenticatedPrincipalOAuth2AuthorizedClientRepository.class))
            )

            .addFilterAfter(jwtAuthenticationFilter(), SecurityContextPersistenceFilter.class);
    return http.build();
  }// 이것도 마찬가지로 변경 됏음. 과거 사용했던 메소드 밑에 현재 버전에 맞는 메소드가 있음.

  @Bean
  AccessDeniedHandler accessDeniedHandler() {
    return (request, response, e) -> {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      Object principal = authentication != null ? authentication.getPrincipal() : null;
      log.warn("{} is denied", principal, e);
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("text/plain");
      response.getWriter().write("### Access Denied ###");
      response.getWriter().flush();
      response.getWriter().close();
    };
  }// 접근 거부 핸들러

  static class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    private static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
      var user = (User) authentication.get().getPrincipal();
      var userName = user.getUsername();
      var matcher = PATTERN.matcher(userName);
      if (matcher.find()) {
        var num = Integer.parseInt(matcher.group());
        if (num % 2 == 0) {
          return new AuthorizationDecision(true);
        }
      }
      return new AuthorizationDecision(false);
    }
  }/*
     커스텀 권한 매니저 -> Spring security 6버전이 되면서 filterSecurityInterceptor가 deprecated 됏음.
     새로운 간소화된 AuthorizationManager API와 AuthorizationFilter를 사용하도록 변경 됏음. 그래서 커스텀 할때는
     AuthorizationManager를 상속받아서 사용하면 됨 대충 위와 같고 더 자세히 알고 싶으면 대표적인 구현체인 WebExpressionAuthorizationManager를 참고하면 됨.
    */

  @Bean
  public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
    return roleHierarchy;
  }/*
       계층형 권한 설정 스프링 시큐리티 버전 6.0에 추가된 내용.
       계층형 권한 설정을 통해 ROLE_ADMIN이 ROLE_USER보다 상위 권한이라는 것을 설정함.
     */


  static class HierarchyBasedAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final RoleHierarchy roleHierarchy;

    public HierarchyBasedAuthorizationManager(RoleHierarchy roleHierarchy) {
      this.roleHierarchy = roleHierarchy;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
      var userAuthorities = authentication.get().getAuthorities();
      var reachableAuthorities = roleHierarchy.getReachableGrantedAuthorities(userAuthorities);

      var hasUserRole = reachableAuthorities.stream()
              .anyMatch(auth -> "ROLE_USER".equals(auth.getAuthority()));

      return new AuthorizationDecision(hasUserRole);
    }
  }
}
