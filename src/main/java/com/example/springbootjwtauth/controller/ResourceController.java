package com.example.springbootjwtauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(ResourceController.BASE_URL)
public class ResourceController {

    public static final String BASE_URL = "/resource";

    @GetMapping("/hello")
    public String hello() {
        return "<h1>Hello World!</h1>";
    }
}
