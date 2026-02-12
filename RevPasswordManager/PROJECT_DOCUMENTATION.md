# RevPasswordManager Project Documentation

**Date:** January 25, 2026
**Version:** 1.0
**Author:** Revature / Development Team

---

## 1. Executive Summary

**RevPasswordManager** is a secure, console-based password management application built with Java. It allows users to store credentials for various websites locally in an encrypted format. The system emphasizes security best practices, including **BCrypt** hashing for master passwords and **AES-256** encryption for stored credentials.

It connects to an **Oracle Database** (21c Express Edition) to persist user data, credentials, and security questions for account recovery.

## 2. Technical Architecture

### 2.1 Technology Stack
- **Language:** Java 17
- **Build Tool:** Maven (3.9.6)
- **Database:** Oracle Database 21c (Service: `XEPDB1`)
- **Key Libraries:**
    - `ojdbc8` (Oracle JDBC Driver)
    - `jbcrypt` (Password Hashing)
    - `log4j-core` / `log4j-api` (Logging)

### 2.2 Application Layers
1.  **Presentation Layer (`App`)**: `PasswordManagerApp.java` handles the main loop, menu display, and user input via console.
2.  **Service Layer (`Service`)**: `PasswordManagerService.java` contains business logic (Authentication, Encryption management, Input validation).
3.  **Data Access Layer (`DAO`)**: `UserDao.java`, `PasswordDao.java`, and `UserAccountDaoImpl.java` handle SQL queries and database transactions.
4.  **Model Layer (`Model`)**: POJOs (`User`, `Credential`, `SecurityQuestion`) representing database entities.
5.  **Utility Layer (`Util`)**:
    - `CryptoUtil.java`: Handles low-level AES encryption/decryption and BCrypt hashing.
    - `ConsoleUtil.java`: Helper for robust console input (masking passwords, handling types).
    - `DatabaseConnection.java`: Singleton for managing JDBC connections.

## 3. Database Schema

The application uses three main tables.

### `USERS`
Stores user identity.
| Column | Type | Description |
|--------|------|-------------|
| `ID` | NUMBER (PK) | Auto-incrementing User ID |
| `USERNAME` | VARCHAR2 | Unique login username |
| `MASTER_PASSWORD_HASH` | VARCHAR2 | BCrypt hash of master password |
| `NAME` | VARCHAR2 | Full name |
| `EMAIL` | VARCHAR2 | User email |

### `CREDENTIALS`
Stores encrypted passwords.
| Column | Type | Description |
|--------|------|-------------|
| `ID` | NUMBER (PK) | Auto-incrementing Credential ID |
| `USER_ID` | NUMBER (FK) | Owner User ID |
| `ACCOUNT_NAME` | VARCHAR2 | e.g. "Google", "Facebook" |
| `USERNAME` | VARCHAR2 | Login for the site |
| `ENCRYPTED_PASSWORD` | VARCHAR2 | AES encrypted password |
| `URL` | VARCHAR2 | Website URL |
| `NOTES` | VARCHAR2 | Optional notes |

### `SECURITY_QUESTIONS`
Stores recovery questions.
| Column | Type | Description |
|--------|------|-------------|
| `ID` | NUMBER (PK) | Auto-incrementing ID |
| `USER_ID` | NUMBER (FK) | Owner User ID |
| `QUESTION` | VARCHAR2 | The question text |
| `ANSWER_HASH` | VARCHAR2 | BCrypt hash of the answer |

## 4. Setup & Installation

### 4.1 Prerequisites
- Java JDK 17+ installed.
- Oracle Database 21c Express Edition installed and running.
- Maven (optional, wrapper provided).

### 4.2 Database Configuration
1.  Create a user in Oracle DB (e.g., `revpass`/`revpass`).
2.  Run the DDL scripts (not included here, but implied by schemas above).
3.  Update `src/main/resources/db.properties`:
    ```ini
    db.url=jdbc:oracle:thin:@localhost:1521/XEPDB1
    db.username=revpass
    db.password=revpass
    ```

### 4.3 Running the Application
Use the provided Maven wrapper/script:
```powershell
.\.mvn-bin\apache-maven-3.9.6\bin\mvn.cmd process-resources exec:java -Dexec.mainClass=com.revpasswordmanager.PasswordManagerApp
```

---

## 5. Source Code Appendix

### Main Application

**`src/main/java/com/revpasswordmanager/PasswordManagerApp.java`**
```java
package com.revpasswordmanager;
import com.revpasswordmanager.service.PasswordManagerService;
import com.revpasswordmanager.util.ConsoleUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Scanner;

public class PasswordManagerApp {
    private static final Logger logger = LogManager.getLogger(PasswordManagerApp.class);

    public static void main(String[] args) {
        logger.info("Starting Password Manager Application");
        Scanner scanner = new Scanner(System.in);
        PasswordManagerService service = new PasswordManagerService();

        while (true) {
            System.out.println("\nPassword Manager");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");
            int choice = ConsoleUtil.getIntInput(scanner);

            switch (choice) {
                case 1:
                    service.registerUser(scanner);
                    break;
                case 2:
                    if (service.loginUser(scanner)) {
                        loggedInMenu(scanner, service);
                    }
                    break;
                case 3:
                    logger.info("Exiting application");
                    System.exit(0);
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    private static void loggedInMenu(Scanner scanner, PasswordManagerService service) {
        while (true) {
            System.out.println("\nLogged In Menu");
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
            System.out.println("11. Forgot Password Recovery");
            System.out.println("12. Logout");
            System.out.print("Choose an option: ");
            int choice = ConsoleUtil.getIntInput(scanner);

            switch (choice) {
                case 1:
                    service.generatePassword(scanner);
                    break;
                case 2:
                    service.addCredential(scanner);
                    break;
                case 3:
                    service.listCredentials();
                    break;
                case 4:
                    service.viewCredential(scanner);
                    break;
                case 5:
                    service.updateCredential(scanner);
                    break;
                case 6:
                    service.deleteCredential(scanner);
                    break;
                case 7:
                    service.searchCredential(scanner);
                    break;
                case 8:
                    service.updateProfile(scanner);
                    break;
                case 9:
                    service.changeMasterPassword(scanner);
                    break;
                case 10:
                    service.manageSecurityQuestions(scanner);
                    break;
                case 11:
                    service.recoverPassword(scanner);
                    break;
                case 12:
                    logger.info("Logging out");
                    return;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }
}
```

### Business Logic

**`src/main/java/com/revpasswordmanager/service/PasswordManagerService.java`**
(Partial listing for brevity, key methods shown)
```java
// ... imports ...
public class PasswordManagerService {
    // ... fields ...

    // Fix: Updated to refetch user ID after create
    public void registerUser(Scanner scanner) {
        // ... prompt for details ...
        try {
            userDao.createUser(user);
            User savedUser = userDao.getUserByUsername(username); // Fetch ID
            if (savedUser != null) {
                addSecurityQuestions(scanner, savedUser.getId());
            }
        } catch (SQLException e) { /* ... */ }
    }

    public boolean loginUser(Scanner scanner) {
        // ... gets username/password ...
        // Verifies hash, verifies user, derives encryption key
        if (user != null && CryptoUtil.verifyPassword(masterPassword, user.getMasterPasswordHash())) {
            currentUser = user;
            encryptionKey = CryptoUtil.deriveKey(masterPassword);
            return true;
        }
        return false;
    }
    
    // ... other CRUD methods (addCredential, listCredentials, etc.) ...
}
```

### Data Access Objects

**`src/main/java/com/revpasswordmanager/dao/UserDao.java`**
```java
package com.revpasswordmanager.dao;
import com.revpasswordmanager.model.User;
import com.revpasswordmanager.model.SecurityQuestion;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class UserDao {
    private Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public void createUser(User user) throws SQLException {
        String sql = "INSERT INTO users (username, master_password_hash, name, email) VALUES (?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getMasterPasswordHash());
            pstmt.setString(3, user.getName());
            pstmt.setString(4, user.getEmail());
            pstmt.executeUpdate();
        }
    }

    public User getUserByUsername(String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new User(rs.getInt("id"), username, rs.getString("master_password_hash"),
                        rs.getString("name"), rs.getString("email"));
            }
            return null;
        }
    }

    // ... updateUser, addSecurityQuestion, getSecurityQuestionsByUserId ...
}
```

**`src/main/java/com/revpasswordmanager/dao/PasswordDao.java`**
```java
package com.revpasswordmanager.dao;
import com.revpasswordmanager.model.Credential;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class PasswordDao {
    private Connection connection;

    public PasswordDao(Connection connection) { this.connection = connection; }

    public void addCredential(Credential credential) throws SQLException {
        String sql = "INSERT INTO credentials (user_id, account_name, username, encrypted_password, url, notes) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            // ... set params ...
            pstmt.executeUpdate();
        }
    }

    public List<Credential> getCredentialsByUserId(int userId) throws SQLException {
        // ... SELECT * FROM credentials WHERE user_id = ? ...
        return new ArrayList<>(); 
    }
    
    // ... getCredentialById, updateCredential, deleteCredential, searchCredentialsByAccountName ...
}
```

**`src/main/java/com/revpasswordmanager/dao/UserAccountDaoImpl.java`** (Legacy/Alternative DAO)
*Correctly implemented to avoid duplicate methods.*

### Utilities

**`src/main/java/com/revpasswordmanager/util/CryptoUtil.java`**
Handles `BCrypt` hashing for passwords and `AES/CBC/PKCS5Padding` for credential encryption. Uses a salt and PBKDF2 for key derivation.

**`src/main/java/com/revpasswordmanager/util/ConsoleUtil.java`**
Handles input reading. Updated to robustly handle `Scanner` and whitespace trimming to support both interactive and piped input modes.

**`src/main/java/com/revpasswordmanager/util/DatabaseConnection.java`**
Uses `DriverManager` to connect to Oracle via `db.properties`.

### Configuration

**`src/main/resources/db.properties`**
```ini
db.url=jdbc:oracle:thin:@localhost:1521/XEPDB1
db.username=revpass
db.password=revpass
```

---
*Generated by Agentic AI Assistant*
