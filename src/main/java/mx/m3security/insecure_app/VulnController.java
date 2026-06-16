package mx.m3security.insecure_app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.Set;

@RestController
public class VulnController {

    private static final Path DATA_DIR = Path.of("/var/data").toAbsolutePath().normalize();
    private static final Set<String> FETCH_ALLOWLIST = Set.of("api.example.com");
    private static final SecretKey AES_KEY = generateKey();

    @Value("${spring.datasource.url}")
    private String dbUrl;
    @Value("${spring.datasource.username}")
    private String dbUser;
    @Value("${spring.datasource.password}")
    private String dbPass;

    @GetMapping("/user")
    public String getUser(@RequestParam String id) throws Exception {
        try (Connection c = DriverManager.getConnection(dbUrl, dbUser, dbPass);
             PreparedStatement ps = c.prepareStatement("SELECT name FROM users WHERE id = ?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : "none";
            }
        }
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        InetAddress addr = InetAddress.getByName(host);
        return addr.isReachable(2000) ? "ok" : "unreachable";
    }

    @GetMapping("/file")
    public String readFile(@RequestParam String name) throws IOException {
        Path resolved = DATA_DIR.resolve(name).normalize();
        if (!resolved.startsWith(DATA_DIR)) {
            throw new SecurityException("path traversal blocked");
        }
        return Files.readString(resolved);
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws IOException {
        URI uri = URI.create(url);
        String scheme = uri.getScheme();
        if (!"https".equalsIgnoreCase(scheme) || !FETCH_ALLOWLIST.contains(uri.getHost())) {
            throw new SecurityException("host not allowed");
        }
        try (var in = new URL(uri.toString()).openStream()) {
            return new String(in.readAllBytes());
        }
    }

    @GetMapping("/hash")
    public String hash(@RequestParam String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data.getBytes());
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, AES_KEY, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(digest);
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "<html><body>Hello " + HtmlUtils.htmlEscape(name) + "</body></html>";
    }

    private static SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
