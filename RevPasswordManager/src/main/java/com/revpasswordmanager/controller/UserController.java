package com.revpasswordmanager.controller;

import com.revpasswordmanager.service.IPasswordManagerService;

import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserController {
    private static final Logger logger = LogManager.getLogger(UserController.class);
    private final IPasswordManagerService passwordManagerService;

    public UserController(IPasswordManagerService passwordManagerService) {
        this.passwordManagerService = passwordManagerService;
    }

    public void registerUser(Scanner scanner) {
        logger.info("Received request to register user");
        passwordManagerService.registerUser(scanner);
    }

    public boolean loginUser(Scanner scanner) {
        logger.info("Received request to login user");
        return passwordManagerService.loginUser(scanner);
    }

    public void updateProfile(Scanner scanner) {
        logger.info("Received request to update profile");
        passwordManagerService.updateProfile(scanner);
    }

    public void changeMasterPassword(Scanner scanner) {
        logger.info("Received request to change master password");
        passwordManagerService.changeMasterPassword(scanner);
    }
}
