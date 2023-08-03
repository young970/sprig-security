package com.prgrms.devcourse.configures;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
                    .requestMatchers("/admin").hasRole("ADMIN")
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
            .rememberMeParameter("remember-me")
            .tokenValiditySeconds(300)

            .and()
            .requiresChannel()
            .anyRequest()
            .requiresSecure()

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
    manager.createUser(User.withUsername("admin")
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
