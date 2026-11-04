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

@Controller
public class RegisterController {
    private static final String PENDING_USER = "pending_2fa_user";

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;
    private final QrCodeService qrCodeService;

    public RegisterController(AppUserRepository repository,
                              PasswordEncoder passwordEncoder,
                              TwoFactorService twoFactorService,
                              QrCodeService qrCodeService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.twoFactorService = twoFactorService;
        this.qrCodeService = qrCodeService;
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    /*
     * Konton med 2FA sparas först när användaren har bekräftat en kod från appen.
     * Fram till dess ligger kontot bara i sessionen, så den som avbryter blir inte utelåst.
     */
    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String password,
                           @RequestParam(required = false) boolean enable2fa,
                           HttpSession session,
                           Model model) {

        if (repository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Email already exists.");
            return "register";
        }

        AppUser user = new AppUser();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setTwoFactorEnabled(enable2fa);

        if (enable2fa) {
            user.setTwoFactorSecret(twoFactorService.generateSecret());
            session.setAttribute(PENDING_USER, user);

            addQrCode(user, model);
            return "show-qr";
        }

        repository.save(user);
        return "redirect:/login";
    }

    @PostMapping("/register/confirm-2fa")
    public String confirm2fa(@RequestParam String code,
                             HttpSession session,
                             Model model) {

        AppUser user = (AppUser) session.getAttribute(PENDING_USER);

        if (user == null) {
            model.addAttribute("error", "Session expired. Please register again.");
            return "register";
        }

        if (!code.matches("\\d{6}") ||
                !twoFactorService.verifyCode(user.getTwoFactorSecret(), Integer.parseInt(code))) {
            model.addAttribute("error", "Invalid authentication code. Try again.");
            addQrCode(user, model);
            return "show-qr";
        }

        if (repository.findByEmail(user.getEmail()).isPresent()) {
            session.removeAttribute(PENDING_USER);
            model.addAttribute("error", "Email already exists.");
            return "register";
        }

        repository.save(user);
        session.removeAttribute(PENDING_USER);

        return "redirect:/login?registered";
    }

    private void addQrCode(AppUser user, Model model) {
        String qrUrl = twoFactorService.generateQrUrl(user.getEmail(), user.getTwoFactorSecret());
        model.addAttribute("qrCode", qrCodeService.generateQrCodeBase64(qrUrl));
    }
}
