package inmemoryauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringSecurityConfig {

    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //Здесь мы используем элемент httpBasic() для определения базовой аутентификации внутри bean-компонента SecurityFilterChain
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .formLogin(Customizer.withDefaults())
                .authorizeHttpRequests((authorize) -> {
                    authorize.anyRequest().authenticated();
                }).httpBasic(Customizer.withDefaults()); // настройщик ничего не будет настраивать ( будут применены настройки по умолчанию)
        return http.build();
    }
    //Что мы говорим, вызывая httpBasic() ?
    //При httpBasic()вызове мы сообщаем Spring, что необходимо аутентифицировать запрос, используя значения, переданные в Authorizationзаголовке запроса.
    // Если запрос не аутентифицирован, вы получите возвращенный статус 401 и сообщение об ошибкеUnauthorized

    //Что на самом деле происходит при вызове httpBasic()?
    //При вызове httpBasic()экземпляр BasicAuthenticationFilter добавляется в цепочку фильтров.
    // Затем BasicAuthenticationFilter продолжит попытку аутентификации запроса типичным способом Spring Security. Если аутентификация прошла успешно,
    // результирующий объект Authentication будет помещен в SecurityContextHolder, который затем можно будет использовать для целей аутентификации в будущем.

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails ramesh = User.builder()
                .username("ramesh")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(ramesh, admin);
    }
}