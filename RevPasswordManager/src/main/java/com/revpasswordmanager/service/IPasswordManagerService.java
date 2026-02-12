package com.revpasswordmanager.service;

import java.util.Scanner;

public interface IPasswordManagerService {
    void registerUser(Scanner scanner);

    boolean loginUser(Scanner scanner);

    void generatePassword(Scanner scanner);

    void addCredential(Scanner scanner);

    void listCredentials();

    void viewCredential(Scanner scanner);

    void updateCredential(Scanner scanner);

    void deleteCredential(Scanner scanner);

    void searchCredential(Scanner scanner);

    void updateProfile(Scanner scanner);

    void changeMasterPassword(Scanner scanner);

    void manageSecurityQuestions(Scanner scanner);

    void recoverPassword(Scanner scanner);
}
