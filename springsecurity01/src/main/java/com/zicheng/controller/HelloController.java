package com.zicheng.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 子诚
 * Description：
 * 时间：2020/3/5 17:11
 */
@RestController
public class HelloController {
        //简单测试一下
        @GetMapping("/hello")
        public String hello(){
            return "hello SpringSecurity";
        }
        @GetMapping("admin/hello")
        public String admin(){
            return "hello admin";
        }
        @GetMapping("user/hello")
        public String user(){
            return "hello user";
        }
        @GetMapping("db/hello")
        public String dba(){
            return "hello dba";
        }
}
