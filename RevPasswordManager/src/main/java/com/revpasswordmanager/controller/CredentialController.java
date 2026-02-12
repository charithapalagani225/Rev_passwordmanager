package com.revpasswordmanager.controller;

import com.revpasswordmanager.service.IPasswordManagerService;

import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CredentialController {
    private static final Logger logger = LogManager.getLogger(CredentialController.class);
    private final IPasswordManagerService passwordManagerService;

    public CredentialController(IPasswordManagerService passwordManagerService) {
        this.passwordManagerService = passwordManagerService;
    }

    public void generatePassword(Scanner scanner) {
        logger.info("Received request to generate password");
        passwordManagerService.generatePassword(scanner);
    }

    public void addCredential(Scanner scanner) {
        logger.info("Received request to add credential");
        passwordManagerService.addCredential(scanner);
    }

    public void listCredentials() {
        logger.info("Received request to list credentials");
        passwordManagerService.listCredentials();
    }

    public void viewCredential(Scanner scanner) {
        logger.info("Received request to view credential");
        passwordManagerService.viewCredential(scanner);
    }

    public void updateCredential(Scanner scanner) {
        logger.info("Received request to update credential");
        passwordManagerService.updateCredential(scanner);
    }

    public void deleteCredential(Scanner scanner) {
        logger.info("Received request to delete credential");
        passwordManagerService.deleteCredential(scanner);
    }

    public void searchCredential(Scanner scanner) {
        logger.info("Received request to search credential");
        passwordManagerService.searchCredential(scanner);
    }
}
