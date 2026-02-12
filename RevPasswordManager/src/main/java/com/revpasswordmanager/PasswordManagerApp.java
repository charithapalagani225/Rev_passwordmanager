package com.revpasswordmanager;

import com.revpasswordmanager.controller.CredentialController;
import com.revpasswordmanager.controller.SecurityQuestionController;
import com.revpasswordmanager.controller.UserController;
import com.revpasswordmanager.controller.VerificationCodeController;

import com.revpasswordmanager.service.IPasswordManagerService;
import com.revpasswordmanager.service.PasswordManagerServiceImpl;
import com.revpasswordmanager.util.ConsoleUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Scanner;

public class PasswordManagerApp {
    private static final Logger logger = LogManager.getLogger(PasswordManagerApp.class);

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        IPasswordManagerService service = new PasswordManagerServiceImpl();

        UserController userController = new UserController(service);
        CredentialController credentialController = new CredentialController(service);
        SecurityQuestionController securityQuestionController = new SecurityQuestionController(service);
        VerificationCodeController verificationCodeController = new VerificationCodeController(service);

        boolean running = true;
        while (running) {
            System.out.println("=======================================");
            System.out.println("\nRevature Password Manager Application");
            System.out.println("=======================================");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Forgot Password Recovery");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");
            int choice = ConsoleUtil.getIntInput(scanner);

            switch (choice) {
                case 1:
                    userController.registerUser(scanner);
                    break;
                case 2:
                    if (userController.loginUser(scanner)) {
                        loggedInMenu(scanner, userController, credentialController, securityQuestionController);
                    }
                    break;
                case 3:
                    verificationCodeController.recoverPassword(scanner);
                    break;
                case 4:
                    logger.info("Exiting application");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    private static void loggedInMenu(Scanner scanner, UserController userController,
            CredentialController credentialController, SecurityQuestionController securityQuestionController) {
        while (true) {
            System.out.println("===========================");
            System.out.println("\nLogged In Successfully");
            System.out.println("===========================");
            System.out.println("1. Generate Password");
            System.out.println("2. Add Credential");
            System.out.println("3. List Credentials");
            System.out.println("4. View Credential (Re-enter Master Password)");
            System.out.println("5. Update Credential");
            System.out.println("6. Delete Credential");
            System.out.println("7. Search Credential");
            System.out.println("8. Update Profile");
            System.out.println("9. Change Master Password");
            System.out.println("10. Manage Security Questions");
            System.out.println("11. Logout");
            System.out.print("Choose an option: ");
            int choice = ConsoleUtil.getIntInput(scanner);

            switch (choice) {
                case 1:
                    credentialController.generatePassword(scanner);
                    break;
                case 2:
                    credentialController.addCredential(scanner);
                    break;
                case 3:
                    credentialController.listCredentials();
                    break;
                case 4:
                    credentialController.viewCredential(scanner);
                    break;
                case 5:
                    credentialController.updateCredential(scanner);
                    break;
                case 6:
                    credentialController.deleteCredential(scanner);
                    break;
                case 7:
                    credentialController.searchCredential(scanner);
                    break;
                case 8:
                    userController.updateProfile(scanner);
                    break;
                case 9:
                    userController.changeMasterPassword(scanner);
                    break;
                case 10:
                    securityQuestionController.manageSecurityQuestions(scanner);
                    break;
                case 11:
                    logger.info("Logging out");
                    return;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }
}
