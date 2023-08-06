package com.prgrms.devcourse.configures;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

  private final Logger log = LoggerFactory.getLogger(getClass());

  //스프링 시큐리티 필터 채인을 태우지 않겠다는 의미
  // 불필요한 서버 자원 낭비를 방지
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring()
            .requestMatchers("/assects/**");
  }

  @Bean
  public AccessDecisionManager accessDecisionManager() {
    List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
    decisionVoters.add(new WebExpressionVoter());
    decisionVoters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
    return new UnanimousBased(decisionVoters);
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
//                    .requestMatchers("/admin").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') && isFullyAuthenticated()"))
                    .requestMatchers("/admin").hasAnyRole("ADMIN")
                    .anyRequest().permitAll()
            )
            .formLogin(login->login.defaultSuccessUrl("/")
//                    .loginPage("/my-login")
//                    .usernameParameter("my-username")
//                    .passwordParameter("my-password")
                    .permitAll())

            .logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/")
            .invalidateHttpSession(true)
            .clearAuthentication(true)

            .and()
            .rememberMe()
            .key("my-remember-me")
            .rememberMeParameter("remember-me")
            .tokenValiditySeconds(300)

            .and()
            .requiresChannel()
            .anyRequest()
            .requiresSecure()

            .and()
            .sessionManagement()
            .sessionFixation().changeSessionId()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .invalidSessionUrl("/")
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false)
            .and()

            .and()
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler());

    return http.build();

  }

  @Bean
  UserDetailsService userDetailsService(){
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("user")
            .password("{noop}user123")
            .roles("USER")
            .build());
    manager.createUser(User.withUsername("admin01")
            .password("{noop}admin123")
            .roles("ADMIN")
            .build());
    manager.createUser(User.withUsername("admin02")
            .password("{noop}admin123")
            .roles("ADMIN")
            .build());
    return manager;
  }

  @Bean
  AccessDeniedHandler accessDeniedHandler(){
    return (request, response, e) -> {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      Object principal = authentication != null ? authentication.getPrincipal() : null;
      log.warn("{} is denided", principal, e);
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("text/plain");
      response.getWriter().write("## ACCESS DENIED ##");
      response.getWriter().flush();
      response.getWriter().close();
    };
  }
}
