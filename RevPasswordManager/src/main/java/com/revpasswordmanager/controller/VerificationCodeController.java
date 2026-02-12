package com.revpasswordmanager.controller;

import com.revpasswordmanager.service.IPasswordManagerService;

import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VerificationCodeController {
    private static final Logger logger = LogManager.getLogger(VerificationCodeController.class);
    private final IPasswordManagerService passwordManagerService;

    public VerificationCodeController(IPasswordManagerService passwordManagerService) {
        this.passwordManagerService = passwordManagerService;
    }

    public void recoverPassword(Scanner scanner) {
        logger.info("Received request to recover password");
        passwordManagerService.recoverPassword(scanner);
    }
}
