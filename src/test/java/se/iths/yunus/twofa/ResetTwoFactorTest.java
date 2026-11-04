package se.iths.yunus.twofa;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class ResetTwoFactorTest {

    private static final String EMAIL = "reset@test.se";
    private static final String PASSWORD = "secret123";
    private static final String OLD_SECRET = "OLDSECRETOLDSECR";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setup() {
        repository.deleteAll();
        repository.save(new AppUser(EMAIL, passwordEncoder.encode(PASSWORD), "USER", true, OLD_SECRET));
    }

    @Test
    void wrongPasswordDoesNotStartTheReset() throws Exception {
        mockMvc.perform(post("/reset-2fa").with(csrf()).param("email", EMAIL).param("password", "wrong"))
                .andExpect(view().name("reset-2fa"));
    }

    @Test
    void secretIsKeptUntilTheNewCodeIsConfirmed() throws Exception {
        MockHttpSession session = new MockHttpSession();
        startReset(session);

        mockMvc.perform(post("/reset-2fa/confirm").session(session).with(csrf()).param("code", "000000"))
                .andExpect(view().name("reset-2fa-qr"));

        assertEquals(OLD_SECRET, repository.findByEmail(EMAIL).orElseThrow().getTwoFactorSecret());
    }

    @Test
    void validCodeReplacesTheSecret() throws Exception {
        MockHttpSession session = new MockHttpSession();
        startReset(session);

        String newSecret = (String) session.getAttribute("pending_2fa_reset_secret");
        int code = new GoogleAuthenticator().getTotpPassword(newSecret);

        mockMvc.perform(post("/reset-2fa/confirm").session(session).with(csrf())
                        .param("code", String.format("%06d", code)))
                .andExpect(redirectedUrl("/login?twoFactorReset"));

        String saved = repository.findByEmail(EMAIL).orElseThrow().getTwoFactorSecret();
        assertEquals(newSecret, saved);
        assertNotEquals(OLD_SECRET, saved);
    }

    private void startReset(MockHttpSession session) throws Exception {
        mockMvc.perform(post("/reset-2fa").session(session).with(csrf())
                        .param("email", EMAIL)
                        .param("password", PASSWORD))
                .andExpect(view().name("reset-2fa-qr"));
    }
}
