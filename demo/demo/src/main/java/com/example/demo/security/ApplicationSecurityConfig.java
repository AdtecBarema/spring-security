package com.example.demo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure (HttpSecurity http) throws Exception {

        http
                .authorizeRequests ()
                .antMatchers ("/","index","/css/x","/js/x")
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

}
