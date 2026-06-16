package mx.m3security.insecure_app;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// ponytail: deliberately insecure — fixtures for SAST/secret scanning. DO NOT DEPLOY.
@RestController
public class VulnController {

    // Hardcoded credentials (SAST: hardcoded-credentials)
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "P@ssw0rd123!";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String JWT_SECRET = "supersecretjwtsigningkey-do-not-share";
    private static final String SECURE_PASSWORD = "P@ssw0rd123!";

    // SQL Injection (CWE-89)
    @GetMapping("/user")
    public String getUser(@RequestParam String id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:test", DB_USER, DB_PASS);
        Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        return rs.next() ? rs.getString(1) : "none";
    }

    // Command Injection (CWE-78)
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        Process p = Runtime.getRuntime().exec("ping -n 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    // Path Traversal (CWE-22)
    @GetMapping("/file")
    public String readFile(@RequestParam String name) throws IOException {
        return new String(new FileInputStream("/var/data/" + name).readAllBytes());
    }

    // SSRF (CWE-918)
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws IOException {
        return new String(new URL(url).openStream().readAllBytes());
    }

    // Weak crypto: MD5 + hardcoded DES key (CWE-327, CWE-321)
    @GetMapping("/hash")
    public String hash(@RequestParam String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(data.getBytes());
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("8bytekey".getBytes(), "DES"));
        return Base64.getEncoder().encodeToString(cipher.doFinal(digest));
    }

    // Insecure deserialization (CWE-502)
    @GetMapping("/load")
    public String load(@RequestParam String blob) throws Exception {
        byte[] data = Base64.getDecoder().decode(blob);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject().toString();
    }

    // Reflected XSS (CWE-79)
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "<html><body>Hello " + name + "</body></html>";
    }
}
