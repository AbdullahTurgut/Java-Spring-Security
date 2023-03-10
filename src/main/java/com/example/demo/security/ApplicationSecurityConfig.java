package com.example.demo.security;


import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserPermission.*;
import static com.example.demo.security.ApplicationUserRole.*;


//@EnableMethodSecurity(prePostEnabled = true)
@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    //Bu aslında "password" şifresini BCripty şifreye uyarlıyor.
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {


        // ROLE BASE AUTHENTICATION

        httpSecurity
                // requestMatchers sıralaması önemli!!
//               .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//               .and()
                .csrf().disable() // crsf -> Cross Site Request Forgery(token somekind)
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .addFilter(new JwtUsernameAndPasswordAuthenticationFiter(authentication -> authentication, jwtConfig, secretKey))
                    .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFiter.class)
                .authorizeHttpRequests()
                    .requestMatchers("/api/**").hasRole(STUDENT.name()) // api student tarafından erişilebilir oldu
                    .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()).requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.name())
                    .requestMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .requestMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
//                .and()
//                .httpBasic(); // FOR BASIC AUTH
        // JWT olduğu için aşağıdaki kısımlara ihtiyaç kalmadı
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll() // FOR FORM BASED AUTH
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password") // login.html deki form name kısmı ile aynı
//                    .usernameParameter("username") // login.html deki form name kısmı ile aynı
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))// default to 2 weeks
//                    .key("somethingverysecured")
//                    .rememberMeParameter("remember-me") // login.html deki form name kısmı ile aynı
//                .and()
//                .logout()
//                    .logoutUrl("/logout") //  csrf.disabled olduğu için  get request
//                    .logoutRequestMatcher(new AntPathRequestMatcher("logoutUrl", "GET"))
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login"); // çıkınca tekrar giriş ekranı için

        return httpSecurity.build();
    }


    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    // BU METHOD YERİNE FakeApplicationUserDaoService KULLANICAZ
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails asyaTurgut = User.builder()
//                .username("asya")
//                .password(passwordEncoder.encode("password")) // must be encoded or it will throw an exception -> There is no PasswordEncoder mapped for the id "null"
////                .roles(STUDENT.name()) // ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthority())
//                .build();
//        UserDetails erayUser = User.builder()
//                .username("eray")
//                .password(passwordEncoder.encode("password1"))
////                .roles(ADMIN.name()) // ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthority())
//                .build();
//        UserDetails alcorUser = User.builder()
//                .username("alcor")
//                .password(passwordEncoder.encode("password2"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthority())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                asyaTurgut,
//                erayUser,
//                alcorUser
//        );
//    }
}
