package com.paul.userauthroles;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration

public class SecurityConfig {
   private static final String[] ENDPOINT_WHITELIST = {"/**","/home"};
   public static final String LOGIN_URL = "/login";
   public static final String LOGIN_FAIL_URL = LOGIN_URL + "?error";
   public static final String DEFAULT_SUCCESS_URL = "/home";
   public static final String USERNAME = "username";
   public static final String PASSWORD = "password";
   @Bean
   @Order(1)
   public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
      http
              .authorizeHttpRequests(request ->
                      request.requestMatchers(ENDPOINT_WHITELIST).hasRole("USER")
                              .anyRequest().authenticated())
              .formLogin(form -> form
                      .loginPage(LOGIN_URL)
                      .failureForwardUrl(LOGIN_FAIL_URL)
                      .usernameParameter(USERNAME)
                      .passwordParameter(PASSWORD)
                      .defaultSuccessUrl(DEFAULT_SUCCESS_URL))
              .logout(logout -> logout
                      .logoutUrl("/logout")
                      .logoutSuccessUrl("/"))
              .sessionManagement(session -> session
                      .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                      .invalidSessionUrl("/invalidSessions")
                      .maximumSessions(1)
                      .maxSessionsPreventsLogin(true));
      return http.build();
   }

}
