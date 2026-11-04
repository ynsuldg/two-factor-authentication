package se.iths.yunus.twofa;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class RegisterTwoFactorTest {

    private static final String EMAIL = "2fa@test.se";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository repository;

    @BeforeEach
    void setup() {
        repository.deleteAll();
    }

    @Test
    void accountWithTwoFactorIsNotSavedBeforeCodeIsConfirmed() throws Exception {
        MockHttpSession session = new MockHttpSession();

        register(session);

        assertFalse(repository.findByEmail(EMAIL).isPresent());
    }

    @Test
    void invalidCodeKeepsTheAccountUnsaved() throws Exception {
        MockHttpSession session = new MockHttpSession();
        register(session);

        mockMvc.perform(post("/register/confirm-2fa").session(session).with(csrf()).param("code", "000000"))
                .andExpect(view().name("show-qr"));

        assertFalse(repository.findByEmail(EMAIL).isPresent());
    }

    @Test
    void validCodeSavesTheAccountWithTwoFactor() throws Exception {
        MockHttpSession session = new MockHttpSession();
        register(session);

        AppUser pending = (AppUser) session.getAttribute("pending_2fa_user");
        int code = new GoogleAuthenticator().getTotpPassword(pending.getTwoFactorSecret());

        mockMvc.perform(post("/register/confirm-2fa").session(session).with(csrf())
                        .param("code", String.format("%06d", code)))
                .andExpect(redirectedUrl("/login?registered"));

        AppUser saved = repository.findByEmail(EMAIL).orElseThrow();
        assertTrue(saved.isTwoFactorEnabled());
    }

    private void register(MockHttpSession session) throws Exception {
        mockMvc.perform(post("/register").session(session).with(csrf())
                        .param("email", EMAIL)
                        .param("password", "secret123")
                        .param("enable2fa", "true"))
                .andExpect(view().name("show-qr"));
    }
}
