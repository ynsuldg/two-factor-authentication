package se.iths.yunus.twofa.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;
import se.iths.yunus.twofa.service.QrCodeService;
import se.iths.yunus.twofa.service.TwoFactorService;

/*
 * Demoåterställning av tvåfaktorsautentisering för den som har tappat sin authenticator-app.
 * E-post och lösenord räcker för att få en ny QR-kod, och den nya hemligheten sparas först
 * när en kod från appen har bekräftats.
 */
@Controller
public class TwoFactorResetController {
    private static final String PENDING_EMAIL = "pending_2fa_reset_email";
    private static final String PENDING_SECRET = "pending_2fa_reset_secret";

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;
    private final QrCodeService qrCodeService;

    public TwoFactorResetController(AppUserRepository repository,
                                    PasswordEncoder passwordEncoder,
                                    TwoFactorService twoFactorService,
                                    QrCodeService qrCodeService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.twoFactorService = twoFactorService;
        this.qrCodeService = qrCodeService;
    }

    @GetMapping("/reset-2fa")
    public String reset2faPage() {
        return "reset-2fa";
    }

    @PostMapping("/reset-2fa")
    public String reset2fa(@RequestParam String email,
                           @RequestParam String password,
                           HttpSession session,
                           Model model) {

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("error", "Invalid email or password.");
            return "reset-2fa";
        }

        if (!user.isTwoFactorEnabled()) {
            model.addAttribute("error", "Two-factor authentication is not enabled for this account.");
            return "reset-2fa";
        }

        String secret = twoFactorService.generateSecret();
        session.setAttribute(PENDING_EMAIL, email);
        session.setAttribute(PENDING_SECRET, secret);

        addQrCode(email, secret, model);
        return "reset-2fa-qr";
    }

    @PostMapping("/reset-2fa/confirm")
    public String confirmReset(@RequestParam String code,
                               HttpSession session,
                               Model model) {

        String email = (String) session.getAttribute(PENDING_EMAIL);
        String secret = (String) session.getAttribute(PENDING_SECRET);

        if (email == null || secret == null) {
            model.addAttribute("error", "Session expired. Please start the reset again.");
            return "reset-2fa";
        }

        if (!code.matches("\\d{6}") || !twoFactorService.verifyCode(secret, Integer.parseInt(code))) {
            model.addAttribute("error", "Invalid authentication code. Try again.");
            addQrCode(email, secret, model);
            return "reset-2fa-qr";
        }

        AppUser user = repository.findByEmail(email).orElse(null);
        session.removeAttribute(PENDING_EMAIL);
        session.removeAttribute(PENDING_SECRET);

        if (user == null) {
            model.addAttribute("error", "Account not found.");
            return "reset-2fa";
        }

        user.setTwoFactorSecret(secret);
        repository.save(user);

        return "redirect:/login?twoFactorReset";
    }

    private void addQrCode(String email, String secret, Model model) {
        String qrUrl = twoFactorService.generateQrUrl(email, secret);
        model.addAttribute("qrCode", qrCodeService.generateQrCodeBase64(qrUrl));
    }
}
