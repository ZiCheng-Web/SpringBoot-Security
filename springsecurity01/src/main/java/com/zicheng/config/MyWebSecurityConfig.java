package com.zicheng.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * 子诚
 * Description：
 * 时间：2020/3/5 17:34
 */

/**
 * 创建一个类并继承WebSecurityConfigurerAdapter这个方法，并在之类中重写configure的3个方法，
 * 其中3个方法中参数包括为HttpSecurity（HTTP请求安全处理），
 * AuthenticationManagerBuilder（身份验证管理生成器）
 * WebSecurity（WEB安全）。
 */
//@Configuration
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    //@Bean
    PasswordEncoder passwordEncoder() {
        //不对密码进行加密
        return NoOpPasswordEncoder.getInstance();
    }

    //AuthenticationManagerBuilder（身份验证管理生成器）
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("root").password("123").roles("ADMIN", "DBA")
                .and()
                //配置了用户为admin，密码为123，角色为admin和user
                .withUser("admin").password("123").roles("ADMIN", "USER")
                .and()
                .withUser("wang").password("123").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //antMatchers:单词意思，反匹配
                //访问“/admin/** ”模式的 URL 必须具备 ADMIN 的角色
                .antMatchers("/admin/**").hasRole("ADMIN")
                //访问 “ /user/**”模式的 URL 必须具备 ADMIN 或者 USER 的角色
                .antMatchers("/user/**").access("hasAnyRole('ADMIN','USER')")
                //访问
                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
                //除了上面的URL模式之外，，用户访问其他的 URL 都必须认证后访问（登录后访问）
                .anyRequest().authenticated()
                .and()
                //表示和登录相关的接口都不需要认证即可访问。
                .formLogin()
                //跳转到登陆页面/login_page，访问URL依旧是/login
                .loginPage("/login_page")
                .loginProcessingUrl("/login")
                //用户名参数为name,密码参数为passwd
                .usernameParameter("name").passwordParameter("passwd")
                //登陆成功处理器
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        Authentication auth)
                            throws IOException {
                        //auth:用来获取当前用户的信息，比如会返回用户的角色
                        Object principal = auth.getPrincipal();
                        //以JSON的形式返回至前端
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(200);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", principal);
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
//                .successForwardUrl("/hello")
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        AuthenticationException e)
                        //AuthenticationException e，通过这个异常参数可以获取登录失败的原因，进而给用户一个明确的提示
                            throws IOException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(401);
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 401);
                        if (e instanceof LockedException) {
                            map.put("msg", "账户被锁定，登录失败!");
                        } else if (e instanceof BadCredentialsException) {
                            map.put("msg", "账户名或密码输入错误，登录失败!");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "账户被禁用，登录失败!");
                        } else if (e instanceof AccountExpiredException) {
                            map.put("msg", "账户已过期，登录失败!");
                        } else if (e instanceof CredentialsExpiredException) {
                            map.put("msg", "密码已过期，登录失败!");
                        } else {
                            map.put("msg", "登录失败!");
                        }
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                }).permitAll()
                .and()
                //注销退出功能
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)//清除用户信息
                .invalidateHttpSession(true)//清除用户的session
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest req,
                                       HttpServletResponse resp,
                                       Authentication auth) {

                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req,
                                                HttpServletResponse resp,
                                                Authentication auth)
                            throws IOException {
                        resp.sendRedirect("/login_page");
                    }
                })
                .and()
                //csrf:跨站请求伪造:攻击者构造网站后台某个功能接口的请求地址，诱导用户去点击或者用特殊方法让该请求地址自动加载。
                //关闭CSRF
                .csrf().disable();
    }
}
