package com.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author : Jeffersonnn
 * @date : 2020/2/4
 * @description :
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义授权规则
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll() //首页允许所有人访问
                .antMatchers("/level1/**").hasRole("VIP1")    //特定页面只允许特定用户角色访问
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启自动配置的登录功能，如果没有权限就自动重定向到登录页面(spring security已经封装好了)
        http.formLogin();
        //开启自动配置的注销功能
        http.logout().logoutSuccessUrl("/"); //注销成功后重定向的URL
        //开启记住我功能
        http.rememberMe();
    }

    /**
     * 定义认证规则
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication()
                .withUser("andre").password("password1").roles("VIP1","VIP2")
                .and().withUser("jack").password("password2").roles("VIP1","VIP2","VIP3")
                .and().withUser("natasha").password("password3").roles("VIP1");
    }
}
