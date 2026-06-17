package mx.m3security.insecure_app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class VulnController {

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello, World!";
    }

    public String vulnerableMethod(String userInput) {
        // This is a vulnerable method that could lead to SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        // Execute the query against the database (not implemented here)
        return query; // Just returning the query for demonstration purposes
    }
}
