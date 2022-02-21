package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig (PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure (HttpSecurity http) throws Exception {
        http
                .csrf ().disable ()
                .authorizeRequests ()
                .antMatchers ("/", "index", "/css/x", "/js/x").permitAll ()
                .antMatchers ("/api/**").hasRole (STUDENT.name ()) // This helps to implement role based access
                .anyRequest ()
                .authenticated ()
                .and ()
                .formLogin ();//form based authentication
//                .httpBasic ();
                /* httpBasic():
                 is based on username, password.
                 Everytime client forward request,
                 password and usernames are also supposed to be appended in to the request
                  antMathchers(): can be used to whitelist some of resources which can be accessed by any user
                  regardless of authentication

                  - Chapter3: Order does matter with AntMatchers: The order antMatchers are added is REALLY matters and we got to be careful!!!

                  - Chapter 4: CSRF: Cross Site Request Forgery,
                                References:
                                            https://www.baeldung.com/spring-security-csrf
                                            https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html

                  */
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService () {
        UserDetails annaSmith = User.builder ()
                .username ("annasmith")
                .password (passwordEncoder.encode ("password"))
//                .roles (STUDENT.name ()) //ROLE_STUDENT
                .authorities (STUDENT.getGrantedAuthorities ())
                .build ();

        UserDetails lindaUser=User.builder ()
                .username ("linda")
                .password (passwordEncoder.encode ("password123"))
//                .roles (ADMIN.name ())//ROLE_ADMIN
                .authorities (ADMIN.getGrantedAuthorities ())
                .build ();

        UserDetails tomUser=User.builder ()
                .username ("tom")
                .password (passwordEncoder.encode ("password123"))
//                .roles (ADMINTRINEE.name ())//ROLE_ADMINTRNEE
                .authorities (ADMINTRINEE.getGrantedAuthorities ())
                .build ();

        return new InMemoryUserDetailsManager (
                annaSmith,lindaUser, tomUser
        );
    }
}