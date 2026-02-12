package com.revpasswordmanager.service;

import com.revpasswordmanager.dao.ICredentialDao;
import com.revpasswordmanager.dao.IUserDao;
import com.revpasswordmanager.model.User;
import com.revpasswordmanager.util.CryptoUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class PasswordManagerServiceImplTest {

    @Mock
    private IUserDao userDao;

    @Mock
    private ICredentialDao credentialDao;

    @Mock
    private IOTPService otpService;

    @InjectMocks
    private PasswordManagerServiceImpl passwordManagerService;

    @BeforeEach
    void setUp() throws Exception {
        // Since PasswordManagerServiceImpl creates DAOs in constructor, we might need
        // to inject mocks manually
        // if we didn't have a constructor injection or setter injection.
        // However, InjectMocks tries to inject into the field.
        // But PasswordManagerServiceImpl initializes fields in constructor which might
        // overwrite mocks or be overwritten.
        // Let's use reflection to ensure mocks are set if constructor logic interferes
        // or if we want to be sure.

        setPrivateField(passwordManagerService, "userDao", userDao);
        setPrivateField(passwordManagerService, "credentialDao", credentialDao);
        setPrivateField(passwordManagerService, "otpService", otpService);
    }

    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    @Test
    void testRegisterUser() {
        String input = "testuser\npassword123\nTest Name\ntest@example.com\nquestion1\nanswer1\nquestion2\nanswer2\nquestion3\nanswer3\n";
        InputStream in = new ByteArrayInputStream(input.getBytes());
        Scanner scanner = new Scanner(in);

        when(userDao.getUserByUsername("testuser")).thenReturn(new User(1, "testuser", "hash", "name", "email"));

        passwordManagerService.registerUser(scanner);

        verify(userDao, times(1)).createUser(any(User.class));
    }

    @Test
    void testLoginUser_Success() {
        String password = "password123";
        String hashedPassword = CryptoUtil.hashPassword(password);
        User user = new User("testuser", hashedPassword, "Test Name", "test@example.com");

        when(userDao.getUserByUsername("testuser")).thenReturn(user);

        String input = "testuser\npassword123\n";
        InputStream in = new ByteArrayInputStream(input.getBytes());
        Scanner scanner = new Scanner(in);

        boolean result = passwordManagerService.loginUser(scanner);

        assertTrue(result);
    }

    @Test
    void testLoginUser_Failure() {
        String password = "password123";
        String hashedPassword = CryptoUtil.hashPassword(password);
        User user = new User("testuser", hashedPassword, "Test Name", "test@example.com");

        when(userDao.getUserByUsername("testuser")).thenReturn(user);

        String input = "testuser\nwrongpassword\n";
        InputStream in = new ByteArrayInputStream(input.getBytes());
        Scanner scanner = new Scanner(in);

        boolean result = passwordManagerService.loginUser(scanner);

        assertFalse(result);
    }
}
