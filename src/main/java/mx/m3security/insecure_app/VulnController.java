package mx.m3security.insecure_app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class VulnController {

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello, World!!!!!";
    }
}
