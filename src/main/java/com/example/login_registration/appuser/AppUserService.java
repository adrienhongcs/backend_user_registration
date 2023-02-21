package com.example.login_registration.appuser;

import com.example.login_registration.registration.token.ConfirmationToken;
import com.example.login_registration.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "user with email %s not found";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser) {
        String token = UUID.randomUUID().toString();
        appUserRepository.findByEmail(appUser.getEmail())
                .ifPresentOrElse(user -> saveConfirmationToken(user, token),
                        () -> saveConfirmationTokenForNewUser(appUser, token)
                );

        return token;
    }

    private void saveConfirmationTokenForNewUser(AppUser appUser, String token) {
        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        appUserRepository.save(appUser);
        saveConfirmationToken(appUser, token);
    }

    private void saveConfirmationToken(AppUser appUser, String token) {
        if (appUser.isEnabled()) throw new IllegalStateException("email already taken");
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);
    }

    public int enableAppUser(String email) {
        return appUserRepository.enableAppUser(email);
    }
}
