// DB Connection: DatabaseConnection.java
package com.revpasswordmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {
    private static final Logger logger = LogManager.getLogger(DatabaseConnection.class);
    private static Connection connection;

    public static Connection getConnection() {
        try {
            if (connection == null || connection.isClosed()) {
                java.util.Properties props = new java.util.Properties();
                try (java.io.InputStream input = DatabaseConnection.class.getClassLoader()
                        .getResourceAsStream("db.properties")) {
                    if (input == null) {
                        try (java.io.InputStream fileInput = new java.io.FileInputStream(
                                "src/main/resources/db.properties")) {
                            props.load(fileInput);
                        } catch (java.io.IOException e) {
                            logger.error("Sorry, unable to find db.properties in classpath or file system");
                            return null;
                        }
                    } else {
                        props.load(input);
                    }
                } catch (java.io.IOException ex) {
                    logger.error("Error reading db.properties", ex);
                    return null;
                }

                String url = props.getProperty("db.url");
                String user = props.getProperty("db.username");
                String password = props.getProperty("db.password");
                connection = DriverManager.getConnection(url, user, password);
                logger.info("Database connected");
            }
        } catch (SQLException e) {
            logger.error("Database connection failed", e);
        }
        return connection;
    }
}