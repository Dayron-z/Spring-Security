package com.app.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.naming.NoPermissionException;
import java.beans.Customizer;

@Configuration
@EnableWebSecurity /*Habilitar seguridad web*/
@EnableMethodSecurity /*Nos permite usar anotciones de springSecurity*/
public class SecurityConfig {
    /*Dato importante: Todo_ el flujo que vemos en el diagrama sucede desde que empiezan los filtros personalizados  (DelegatingFilterProxy)*/


/* 1- Primer componente a configurar es el Security filter chain*/
    /*HttpSecurity objeto que pasa todos_ los filtros: Ejemplo, pasa primero por el filtro 1,2,3 etc...*/
    /*HttpSecurity trabaja con el patrón build*/
    /*Definimos como bean*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
/*        "CSRF (Cross-Site Request Forgery) es una vulnerabilidad de seguridad web que permite a un atacante inducir a un usuario autenticado a realizar acciones no deseadas en una aplicación web, aprovechando su sesión activa."*/
                /*En este caso al ser aplicaciones rest no lo necesitamos pero para todo_ el tema de formularios es muy importante*/
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    //Importante, primero configuramos los endpoints públicos y después los privados

                    /*Endpoints públicos*/
                    http.requestMatchers(HttpMethod.GET, "/auth/hello");
                    /*Endpoints privados*/
                    http.requestMatchers(HttpMethod.GET, "/auth/hello-secured").hasAuthority("CREATE");
                    /*Endpoints restantes */
                    http.anyRequest().denyAll();
                })
                .build();
    }

    /* 2- Authentication Manager: Componente que administra la autentitación*/
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        //El authentication manager lo tenemos que crear a partir de un objeto que ya existe en spring security (authenticationConfiguration), como tal podemos hacer la inyección de dependencias o se lo pasamos como parametro

        return authenticationConfiguration.getAuthenticationManager();
    }

    /*3 - Necesitamos un proveeedor (Authentication provider)*
    Es una interfaz como tal/*/

    @Bean
    public AuthenticationProvider authenticationProvider(){
        /*DaoAuthenticationProvider es el que se conecta a una base de datos y trae a los usuasrios, como tal AuthenticationProvider tiene varios provider, elegir el necesario, en este caso usaremos este */

        /* var se introdujo en Java 10 y se utiliza para la inferencia de tipos en la declaración de variables locales,*/
        var provider = new DaoAuthenticationProvider();
        /*El provider necesita dos componentes (Según el flujo en que nos basamos)*/
        /*Seteos en base al flujo del diagrama*/
        provider.setPasswordEncoder(null);
        provider.setUserDetailsService(null);
        /*Primeramente lo seteamos como null, pero no pueden quedar así, procedemos a crearlos*/

        return provider;
    }



    //Simulación de usuarios traidos de una base de datos
    //Dato importante: Spring security entiende o valida los usuarios a través del objeto
    //UserDetailsService, por ende cuando traigamos los usuarios de una base de datos real, los tendremos que convertir a un UserDetailService
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails userDetails = User
                .withUsername("santiago")
                .password("12345")
                .authorities("READ", "CREATE")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        //Usamos NoOpPasswordEncoder únicamente para pruebas, ya que como tal no encripta
        //El que usaremos en un futuro será  BCryptPasswordEncoder, que si encripta como tal la contraseña
        return NoOpPasswordEncoder.getInstance();
    }


}
