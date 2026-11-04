package se.iths.yunus.twofa.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;

import java.nio.charset.StandardCharsets;

@Controller
public class AccountController {
    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public AccountController(AppUserRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/reset-password")
    public String resetPasswordPage() {
        return "reset-password";
    }

    /*
     * Demoåterställning utan verifiering av kontots ägare, samma som i Agile Webshop.
     * Den som känner till e-postadressen kan sätta ett nytt lösenord.
     * Tvåfaktorsautentiseringen behålls, så inloggningen kräver fortfarande koden.
     */
    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String email,
                                @RequestParam String password,
                                @RequestParam String confirmPassword,
                                Model model) {

        if (password.length() < 8 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            model.addAttribute("error", "Password must be between 8 and 72 characters.");
            return "reset-password";
        }

        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match.");
            return "reset-password";
        }

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null) {
            model.addAttribute("error", "Account not found.");
            return "reset-password";
        }

        user.setPassword(passwordEncoder.encode(password));
        repository.save(user);

        return "redirect:/login?reset";
    }

    @PostMapping("/delete-account")
    public String deleteAccount(@RequestParam String password,
                                Authentication authentication,
                                HttpServletRequest request,
                                HttpServletResponse response,
                                Model model) {

        AppUser user = repository.findByEmail(authentication.getName()).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("error", "Invalid password. The account was not deleted.");
            return "home";
        }

        repository.delete(user);
        new SecurityContextLogoutHandler().logout(request, response, authentication);

        return "redirect:/login?deleted";
    }
}
