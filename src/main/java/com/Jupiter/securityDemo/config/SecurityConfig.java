package com.Jupiter.securityDemo.config;

import com.Jupiter.securityDemo.jwt.AuthEntryPointJwt;
import com.Jupiter.securityDemo.jwt.AuthTokenFilter;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  @Autowired
  DataSource dataSource;
  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

//  @Bean
//  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//    http.authorizeHttpRequests((requests) -> {
//      ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests.requestMatchers("/h2-console/**")
//          .permitAll()   // allow h2-console
//          .anyRequest()).authenticated();
//    });
//
//    // make no cookie and API stateless
//    http.sessionManagement(
//        (session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)));
//
//    // enabled the frame from the same origin
//    http.headers(headers -> headers.frameOptions(FrameOptionsConfig::sameOrigin));
//    //    http.httpBasic(Customizer.withDefaults());
//
//    http.csrf(csrf -> csrf.disable());
//    return (SecurityFilterChain) http.build();
//  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorizeRequests ->
        authorizeRequests.requestMatchers("/h2-console/**").permitAll()   // allow h2-console
            .requestMatchers("/auth/signin").permitAll()
            .anyRequest().authenticated());

    // make no cookie and API stateless
    http.sessionManagement(
        (session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)));

    // add handler
    http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));

    // enabled the frame from the same origin
    http.headers(headers -> headers.frameOptions(FrameOptionsConfig::sameOrigin));

    http.csrf(csrf -> csrf.disable());

    // add filter
    http.addFilterBefore(authenticationJwtTokenFilter(),
        UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  // Use inmemory to create multi user (UserDetails)
  //  @Bean
  //  public UserDetailsService userDetailsService() {
  //    UserDetails user1 = User.withUsername("user1")
  //        .password(passwordEncoder().encode("password1"))
  //        .roles("USER").build();
  //
  //    UserDetails admin = User.withUsername("admin")
  //        .password(passwordEncoder().encode("adminpass"))
  //        .roles("ADMIN").build();
  //
  //    return new JdbcUserDetailsManager(dataSource);
  //    //  return new InMemoryUserDetailsManager(user1, admin);
  //  }

  @Bean
  public UserDetailsService userDetailsService() {
      return new JdbcUserDetailsManager(dataSource);
  }

  // add user creation in initialize process
  @Bean
  public CommandLineRunner initData(UserDetailsService userDetailsService) {
    return args -> {
      JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
      UserDetails user1 = User.withUsername("user1")
          .password(passwordEncoder().encode("password1"))
          .roles("USER")
          .build();

      UserDetails admin = User.withUsername("admin")
          .password(passwordEncoder().encode("adminpass"))
          .roles("ADMIN")
          .build();

      // save user to db BUT create schema first
      JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
      userDetailsManager.createUser(user1);
      userDetailsManager.createUser(admin);
    };
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration builder)
      throws Exception {
    return builder.getAuthenticationManager();
  }
}