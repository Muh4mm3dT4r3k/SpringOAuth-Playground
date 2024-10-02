package com.mohamed.authorizationserver.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerFilterChain(HttpSecurity httpSecurity) throws Exception {
        // Apply OAuth 2.0 Authorization Server default security settings
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        // Enable OIDC
        httpSecurity
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // Enforce HTTPS
//        httpSecurity.requiresChannel(channel -> channel.anyRequest().requiresSecure());

        // Customize exception handling to redirect unauthenticated users to /login
        httpSecurity.exceptionHandling(e -> {
            e.authenticationEntryPoint(
                    new LoginUrlAuthenticationEntryPoint("/login")
            );
        });

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .formLogin(Customizer.withDefaults())
                .authorizeHttpRequests(requestMatcherRegistry -> {
                    requestMatcherRegistry.anyRequest().authenticated();
                })
                .build();

    }
}
