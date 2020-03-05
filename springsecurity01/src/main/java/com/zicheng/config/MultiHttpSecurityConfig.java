package com.zicheng.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MultiHttpSecurityConfig {
    /*
     BCryptPasswordEncoder 使用 BCrypt 强哈希函数，
     开发者在使用时可以选择提供由 strength 和 SecureRandom 实例， strength 越大，密钥的迭代次数越多，密钥 是代次数为2的strength次方，
      strength 取值在4--31 之间，默认为 10
      SecureRandom生成真随机数，采用的是类似于密码学的随机数生成规则，其输出结果较难预测
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //密码，同样是123。由于迭代次数和真随机数的不同，加密后的密码也是不一样
        auth.inMemoryAuthentication()
                .withUser("root").password("$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq")
                .roles("ADMIN", "DBA")

                .and()
                .withUser("admin").password("$2a$10$RMuFXGQ5AtH4wOvkUqyvuecpqUSeoxZYqilXzbz50dceRsga.WYiq")
                .roles("ADMIN", "USER")

                .and()
                .withUser("sang")
                .password("$2a$10$eUHbAOMq4bpxTvOVz33LIehLe3fu6NwqC9tdOcxJXEhyZ4simqXTC")
                .roles("USER");
    }

    /**
     * 配置多个 HTTPpSecurity时，MultiHttpSecurityConfig 不需要继承 WebSecurityConfigurerAdapter,
     * 在 MultiHttpSecurityConfig 中创建静态内部类继承 WebSecurityConfigurerAdapter 即可，
     * 静态内部类 添加@Configuration 注解和@Order 注解，
     *
     * @Order 注解表示该配置的优先级，数字小优先级越大，
     * 未配置@Order 解的配置优先级最小
     */
    //表示该类主要用来处理“／admin/**”模式的 URL,其他则由另一个 HttpSecurity 来处理
    @Configuration
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/admin/**").authorizeRequests()
                    .anyRequest().hasRole("ADMIN");
        }
    }

    @Configuration
    public static class OtherSecurityConfig
            extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/login")
                    .permitAll()
                    .and()
                    .csrf()
                    .disable();
        }
    }
}
