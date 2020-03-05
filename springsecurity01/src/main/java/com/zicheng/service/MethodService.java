package com.zicheng.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {
    //@Secured(”ROLE_ AD MIN＂）注解表示访问该方法需要 ADMIN 角色，注意这里需要在角色前加一个前缀ROLE_
    @Secured("ROLE_ADMIN")
    public String admin() {
        return "hello admin";
    }

    //@PreAuthorize("hasRole('ADMIN') and hasRole('DBA')")注解表示访问该方法既需要 ADMIN角色又需要 DBA 角色
    @PreAuthorize("hasRole('ADMIN') and hasRole('DBA')")
    public String dba() {
        return "hello dba";
    }
    //同理
    @PreAuthorize("hasAnyRole('ADMIN','DBA','USER')")
    public String user() {
        return "user";
    }
}
