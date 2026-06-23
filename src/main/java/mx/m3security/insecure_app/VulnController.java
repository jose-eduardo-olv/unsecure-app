package mx.m3security.insecure_app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class VulnController {

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello, World!!!!!";
    }

    public String vulnerableMethod(String userInput) {
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        // This is vulnerable to SQL Injection if userInput is not properly sanitized
        return query;
    }
}
