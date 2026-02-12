package com.revpasswordmanager.service;

import com.revpasswordmanager.dao.ICredentialDao;
import com.revpasswordmanager.dao.CredentialDaoImpl;
import com.revpasswordmanager.dao.IUserDao;
import com.revpasswordmanager.dao.UserDaoImpl;
import com.revpasswordmanager.model.Credential;
import com.revpasswordmanager.model.SecurityQuestion;
import com.revpasswordmanager.model.User;
import com.revpasswordmanager.util.CryptoUtil;
import com.revpasswordmanager.util.ConsoleUtil;
import com.revpasswordmanager.util.DatabaseConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.SecureRandom;
import com.revpasswordmanager.exception.RevPasswordManagerException;
import com.revpasswordmanager.exception.AuthenticationException;
import com.revpasswordmanager.exception.ResourceNotFoundException;
import com.revpasswordmanager.exception.UserAlreadyExistsException;
import java.sql.Connection;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

public class PasswordManagerServiceImpl implements IPasswordManagerService {
    private static final Logger logger = LogManager.getLogger(PasswordManagerServiceImpl.class);
    private IUserDao userDao;
    private ICredentialDao credentialDao;
    private IOTPService otpService;
    private User currentUser;
    private byte[] encryptionKey;

    public PasswordManagerServiceImpl() {
        Connection connection = DatabaseConnection.getConnection();
        this.userDao = new UserDaoImpl(connection);
        this.credentialDao = new CredentialDaoImpl(connection);
        this.otpService = new OTPServiceImpl();
    }

    public void registerUser(Scanner scanner) {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        String masterPassword = ConsoleUtil.getPasswordInput(scanner, "Enter master password: ");
        String name = ConsoleUtil.getStringInput(scanner, "Enter name: ");
        String email = ConsoleUtil.getStringInput(scanner, "Enter email: ");

        String hashedMasterPassword = CryptoUtil.hashPassword(masterPassword);
        User user = new User(username, hashedMasterPassword, name, email);
        try {
            userDao.createUser(user);
            logger.info("User registered: {}", username);
            System.out.println("User registered successfully. Now add security questions.");

            // Fetch the user again to get the generated ID
            User savedUser = userDao.getUserByUsername(username);
            if (savedUser != null) {
                addSecurityQuestions(scanner, savedUser.getId());
            } else {
                logger.error("Error retrieving registered user for security questions");
            }
        } catch (UserAlreadyExistsException e) {
            logger.warn("Registration failed: {}", e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error registering user", e);
            System.out.println("Error registering user.");
        }
    }

    public boolean loginUser(Scanner scanner) {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        String masterPassword = ConsoleUtil.getPasswordInput(scanner, "Enter master password: ");

        try {
            User user = userDao.getUserByUsername(username);
            if (user != null && CryptoUtil.verifyPassword(masterPassword, user.getMasterPasswordHash())) {
                currentUser = user;
                encryptionKey = CryptoUtil.deriveKey(masterPassword);
                logger.info("User logged in: {}", username);
                return true;
            } else {
                throw new AuthenticationException("Invalid username or password");
            }
        } catch (AuthenticationException e) {
            logger.warn("Login failed for user: {}", username);
            System.out.println("Login failed: " + e.getMessage());
            return false;
        } catch (RevPasswordManagerException e) {
            logger.error("Error during login", e);
            return false;
        }
    }

    public void generatePassword(Scanner scanner) {
        int length = ConsoleUtil.getIntInput(scanner, "Enter password length: ");
        boolean useUpper = ConsoleUtil.getBooleanInput(scanner, "Include uppercase? (y/n): ");
        boolean useDigits = ConsoleUtil.getBooleanInput(scanner, "Include digits? (y/n): ");
        boolean useSpecial = ConsoleUtil.getBooleanInput(scanner, "Include special chars? (y/n): ");

        String chars = "abcdefghijklmnopqrstuvwxyz";
        if (useUpper)
            chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useDigits)
            chars += "0123456789";
        if (useSpecial)
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        System.out.println("Generated password: " + password);
    }

    public void addCredential(Scanner scanner) {
        if (currentUser == null)
            return;
        String accountName = ConsoleUtil.getStringInput(scanner, "Account name: ");
        String credUsername = ConsoleUtil.getStringInput(scanner, "Username: ");
        String password = ConsoleUtil.getPasswordInput(scanner, "Password: ");
        String url = ConsoleUtil.getStringInput(scanner, "URL (optional): ");
        String notes = ConsoleUtil.getStringInput(scanner, "Notes (optional): ");

        String encryptedPassword = CryptoUtil.encrypt(password, encryptionKey);
        Credential credential = new Credential(currentUser.getId(), accountName, credUsername, encryptedPassword, url,
                notes);
        try {
            credentialDao.addCredential(credential);
            logger.info("Credential added for account: {}", accountName);
            System.out.println("Credential added.");
        } catch (RevPasswordManagerException e) {
            logger.error("Error adding credential", e);
        }
    }

    public void listCredentials() {
        if (currentUser == null)
            return;
        try {
            List<Credential> credentials = credentialDao.getCredentialsByUserId(currentUser.getId());
            if (credentials.isEmpty()) {
                System.out.println("No credentials found.");
            } else {
                System.out.println("Credentials:");
                for (Credential cred : credentials) {
                    System.out.println("ID: " + cred.getId() + ", Account: " + cred.getAccountName() + ", Username: "
                            + cred.getUsername());
                }
            }
        } catch (RevPasswordManagerException e) {
            logger.error("Error listing credentials", e);
        }
    }

    public void viewCredential(Scanner scanner) {
        if (currentUser == null)
            return;
        String reEnterMaster = ConsoleUtil.getPasswordInput(scanner, "Re-enter master password: ");
        if (!CryptoUtil.verifyPassword(reEnterMaster, currentUser.getMasterPasswordHash())) {
            System.out.println("Incorrect master password.");
            return;
        }

        int credId = ConsoleUtil.getIntInput(scanner, "Enter credential ID: ");
        try {
            Credential cred = credentialDao.getCredentialById(credId, currentUser.getId());
            if (cred != null) {
                String decryptedPassword = CryptoUtil.decrypt(cred.getEncryptedPassword(), encryptionKey);
                System.out.println("Account: " + cred.getAccountName());
                System.out.println("Username: " + cred.getUsername());
                System.out.println("Password: " + decryptedPassword);
                System.out.println("URL: " + cred.getUrl());
                System.out.println("Notes: " + cred.getNotes());
            } else {
                throw new ResourceNotFoundException("Credential not found with ID: " + credId);
            }
        } catch (ResourceNotFoundException e) {
            logger.warn(e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error viewing credential", e);
        }
    }

    // Similarly implement updateCredential, deleteCredential, searchCredential,
    // updateProfile, changeMasterPassword

    public void updateCredential(Scanner scanner) {
        if (currentUser == null)
            return;
        int credId = ConsoleUtil.getIntInput(scanner, "Enter credential ID to update: ");
        try {
            Credential cred = credentialDao.getCredentialById(credId, currentUser.getId());
            if (cred == null) {
                throw new ResourceNotFoundException("Credential not found with ID: " + credId);
            }
            // Prompt for new values, encrypt new password if changed
            String newPassword = ConsoleUtil.getPasswordInput(scanner, "New password (leave blank to keep current): ");
            if (!newPassword.isEmpty()) {
                cred.setEncryptedPassword(CryptoUtil.encrypt(newPassword, encryptionKey));
            }
            // Update other fields similarly
            credentialDao.updateCredential(cred);
            System.out.println("Credential updated.");
        } catch (ResourceNotFoundException e) {
            logger.warn(e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error updating credential", e);
        }
    }

    public void deleteCredential(Scanner scanner) {
        if (currentUser == null)
            return;
        int credId = ConsoleUtil.getIntInput(scanner, "Enter credential ID to delete: ");
        try {
            Credential cred = credentialDao.getCredentialById(credId, currentUser.getId());
            if (cred == null) {
                throw new ResourceNotFoundException("Credential not found with ID: " + credId);
            }
            credentialDao.deleteCredential(credId, currentUser.getId());
            System.out.println("Credential deleted.");
        } catch (ResourceNotFoundException e) {
            logger.warn(e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error deleting credential", e);
        }
    }

    public void searchCredential(Scanner scanner) {
        if (currentUser == null)
            return;
        String accountName = ConsoleUtil.getStringInput(scanner, "Enter account name to search: ");
        try {
            List<Credential> credentials = credentialDao.searchCredentialsByAccountName(currentUser.getId(),
                    accountName);
            if (credentials.isEmpty()) {
                System.out.println("No matching credentials.");
            } else {
                for (Credential cred : credentials) {
                    System.out.println("ID: " + cred.getId() + ", Account: " + cred.getAccountName() + ", Username: "
                            + cred.getUsername());
                }
            }
        } catch (RevPasswordManagerException e) {
            logger.error("Error searching credentials", e);
        }
    }

    public void updateProfile(Scanner scanner) {
        if (currentUser == null)
            return;
        String newName = ConsoleUtil.getStringInput(scanner, "New name (leave blank to keep): ");
        String newEmail = ConsoleUtil.getStringInput(scanner, "New email (leave blank to keep): ");
        if (!newName.isEmpty())
            currentUser.setName(newName);
        if (!newEmail.isEmpty())
            currentUser.setEmail(newEmail);
        try {
            userDao.updateUser(currentUser);
            System.out.println("Profile updated.");
        } catch (RevPasswordManagerException e) {
            logger.error("Error updating profile", e);
        }
    }

    public void changeMasterPassword(Scanner scanner) {
        if (currentUser == null)
            return;
        String oldMaster = ConsoleUtil.getPasswordInput(scanner, "Enter old master password: ");
        if (!CryptoUtil.verifyPassword(oldMaster, currentUser.getMasterPasswordHash())) {
            throw new AuthenticationException("Incorrect old password.");
        }
        String newMaster = ConsoleUtil.getPasswordInput(scanner, "Enter new master password: ");
        String newHash = CryptoUtil.hashPassword(newMaster);
        byte[] newKey = CryptoUtil.deriveKey(newMaster);

        // Re-encrypt all credentials with new key
        try {
            List<Credential> credentials = credentialDao.getCredentialsByUserId(currentUser.getId());
            for (Credential cred : credentials) {
                String decrypted = CryptoUtil.decrypt(cred.getEncryptedPassword(), encryptionKey);
                String reEncrypted = CryptoUtil.encrypt(decrypted, newKey);
                cred.setEncryptedPassword(reEncrypted);
                credentialDao.updateCredential(cred);
            }
            currentUser.setMasterPasswordHash(newHash);
            userDao.updateUser(currentUser);
            encryptionKey = newKey;
            System.out.println("Master password changed.");
        } catch (AuthenticationException e) {
            logger.warn(e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error changing master password", e);
        }
    }

    private void addSecurityQuestions(Scanner scanner, int userId) {
        for (int i = 1; i <= 3; i++) { // Assume 3 questions
            String question = ConsoleUtil.getStringInput(scanner, "Security question " + i + ": ");
            String answer = ConsoleUtil.getPasswordInput(scanner, "Answer: ");
            String hashedAnswer = CryptoUtil.hashPassword(answer);
            SecurityQuestion sq = new SecurityQuestion(userId, question, hashedAnswer);
            try {
                userDao.addSecurityQuestion(sq);
            } catch (RevPasswordManagerException e) {
                logger.error("Error adding security question", e);
            }
        }
    }

    public void manageSecurityQuestions(Scanner scanner) {
        if (currentUser == null)
            return;

        while (true) {
            System.out.println("Manage Security Questions:");
            System.out.println("1. List Questions");
            System.out.println("2. Add Question");
            System.out.println("3. Update Question");
            System.out.println("4. Delete Question");
            System.out.println("5. Back");
            System.out.print("Choose an option: ");
            int choice = ConsoleUtil.getIntInput(scanner);

            try {
                switch (choice) {
                    case 1:
                        List<SecurityQuestion> questions = userDao.getSecurityQuestionsByUserId(currentUser.getId());
                        if (questions.isEmpty()) {
                            System.out.println("No security questions found.");
                        } else {
                            for (SecurityQuestion q : questions) {
                                System.out.println("ID: " + q.getId() + ", Question: " + q.getQuestion());
                            }
                        }
                        break;
                    case 2:
                        String question = ConsoleUtil.getStringInput(scanner, "Enter new question: ");
                        String answer = ConsoleUtil.getPasswordInput(scanner, "Enter answer: ");
                        String hashedAnswer = CryptoUtil.hashPassword(answer);
                        SecurityQuestion newSq = new SecurityQuestion(currentUser.getId(), question, hashedAnswer);
                        userDao.addSecurityQuestion(newSq);
                        System.out.println("Security question added.");
                        break;
                    case 3:
                        int updateId = ConsoleUtil.getIntInput(scanner, "Enter question ID to update: ");
                        SecurityQuestion sqToUpdate = userDao.getSecurityQuestionById(updateId);
                        if (sqToUpdate != null && sqToUpdate.getUserId() == currentUser.getId()) {
                            String newQ = ConsoleUtil.getStringInput(scanner, "Enter new question: ");
                            String newA = ConsoleUtil.getPasswordInput(scanner, "Enter new answer: ");
                            sqToUpdate.setQuestion(newQ);
                            sqToUpdate.setAnswerHash(CryptoUtil.hashPassword(newA));
                            userDao.updateSecurityQuestion(sqToUpdate);
                            System.out.println("Security question updated.");
                        } else {
                            throw new ResourceNotFoundException(
                                    "Question not found or access denied for ID: " + updateId);
                        }
                        break;
                    case 4:
                        int deleteId = ConsoleUtil.getIntInput(scanner, "Enter question ID to delete: ");
                        SecurityQuestion sqToDelete = userDao.getSecurityQuestionById(deleteId);
                        if (sqToDelete != null && sqToDelete.getUserId() == currentUser.getId()) {
                            userDao.deleteSecurityQuestion(deleteId);
                            System.out.println("Security question deleted.");
                        } else {
                            throw new ResourceNotFoundException(
                                    "Question not found or access denied for ID: " + deleteId);
                        }
                        break;
                    case 5:
                        return;
                    default:
                        System.out.println("Invalid choice.");
                }
            } catch (ResourceNotFoundException e) {
                logger.warn(e.getMessage());
                System.out.println(e.getMessage());
            } catch (RevPasswordManagerException e) {
                logger.error("Error managing security questions", e);
            }
        }
    }

    public void recoverPassword(Scanner scanner) {
        System.out.print("Enter username for recovery: ");
        String username = scanner.nextLine();
        try {
            User user = userDao.getUserByUsername(username);
            if (user == null) {
                throw new ResourceNotFoundException("User not found with username: " + username);
            }
            List<SecurityQuestion> questions = userDao.getSecurityQuestionsByUserId(user.getId());
            boolean verified = true;
            for (SecurityQuestion q : questions) {
                System.out.println(q.getQuestion());
                String answer = ConsoleUtil.getPasswordInput(scanner, "Answer: ");
                if (!CryptoUtil.verifyPassword(answer, q.getAnswerHash())) {
                    verified = false;
                    break;
                }
            }
            if (verified) {
                String verificationCode = otpService.generateOTP(user.getId(), "PASSWORD_RECOVERY");
                System.out.println("Verification code (simulated email): " + verificationCode);

                String inputCode = ConsoleUtil.getStringInput(scanner, "Enter verification code: ");
                if (otpService.validateOTP(user.getId(), inputCode, "PASSWORD_RECOVERY")) {
                    String newMaster = ConsoleUtil.getPasswordInput(scanner, "Enter new master password: ");
                    // Similar to changeMasterPassword, but without old key (assume re-encrypt with
                    // new)
                    // For simplicity, reset all credentials or warn user
                    System.out.println("Password recovered. Note: Existing credentials may need re-addition.");
                    String newHash = CryptoUtil.hashPassword(newMaster);
                    user.setMasterPasswordHash(newHash);
                    userDao.updateUser(user);
                } else {
                    System.out.println("Invalid code.");
                }
            } else {
                System.out.println("Security questions failed.");
            }
        } catch (ResourceNotFoundException e) {
            logger.warn(e.getMessage());
            System.out.println(e.getMessage());
        } catch (RevPasswordManagerException e) {
            logger.error("Error during recovery", e);
        }
    }

}
