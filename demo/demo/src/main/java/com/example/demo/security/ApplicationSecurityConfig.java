package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig (PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure (HttpSecurity http) throws Exception {
        http
                .authorizeRequests ()
                .antMatchers ("/", "index", "/css/x", "/js/x")
                .permitAll ()
                .anyRequest ()
                .authenticated ()
                .and ()
                .httpBasic ();
                /* httpBasic():
                 is based on username, password.
                 Everytime client forward request,
                 password and usernames are also supposed to be appended in to the request
                  antMathchers(): can be used to whitelist some of resources which can be accessed by any user
                  regardless of authentication
                  */
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService () {
        UserDetails annaSmith = User.builder ()
                .username ("annasmith")
                .password (passwordEncoder.encode ("password"))
                .roles (ApplicationUserRole.STUDENT.name ()) //Role_Student
                .build ();

        UserDetails lindaUser=User.builder ()
                .username ("linda")
                .password (passwordEncoder.encode ("password123"))
                .roles (ApplicationUserRole.ADMIN.name ())
                .build ();
        return new InMemoryUserDetailsManager (
                annaSmith,lindaUser
        );
    }
}