package com.template.api.auth;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/user")
public class UserController {

    // TODO: On signup request, new user is created
    @PostMapping("/signup")
    public void createNewUserOnSignup() {}
}
