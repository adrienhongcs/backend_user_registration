package com.example.login_registration.registration;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@AllArgsConstructor
public class EmailValidator implements Predicate<String> {

    private static final Pattern pattern = Pattern.compile("^(.+)@(.+)$");

    @Override
    public boolean test(String s) {
        Matcher matcher = pattern.matcher(s);
        return matcher.matches();
    }
}
