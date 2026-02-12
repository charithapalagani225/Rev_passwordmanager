package com.revpasswordmanager.dao;

import com.revpasswordmanager.exception.RevPasswordManagerException;
import com.revpasswordmanager.model.Credential;
import com.revpasswordmanager.util.DatabaseConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class CredentialDaoImpl implements ICredentialDao {
    private static final Logger logger = LogManager.getLogger(CredentialDaoImpl.class);
    private Connection connection;

    public CredentialDaoImpl(Connection connection) {
        this.connection = connection;
    }

    @Override
    public void addCredential(Credential credential) {
        String sql = "INSERT INTO credentials (user_id, account_name, username, encrypted_password, url, notes) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, credential.getUserId());
            pstmt.setString(2, credential.getAccountName());
            pstmt.setString(3, credential.getUsername());
            pstmt.setString(4, credential.getEncryptedPassword());
            pstmt.setString(5, credential.getUrl());
            pstmt.setString(6, credential.getNotes());
            pstmt.executeUpdate();
            logger.info("Credential added for user ID: {} account: {}", credential.getUserId(),
                    credential.getAccountName());
        } catch (SQLException e) {
            logger.error("Error adding credential", e);
            throw new RevPasswordManagerException("Error adding credential", e);
        }
    }

    @Override
    public List<Credential> getCredentialsByUserId(int userId) {
        List<Credential> credentials = new ArrayList<>();
        String sql = "SELECT id, user_id, account_name, username, encrypted_password, url, notes FROM credentials WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                credentials.add(new Credential(rs.getInt("id"), userId, rs.getString("account_name"),
                        rs.getString("username"), rs.getString("encrypted_password"),
                        rs.getString("url"), rs.getString("notes")));
            }
        } catch (SQLException e) {
            logger.error("Error retrieving credentials for user ID: {}", userId, e);
            throw new RevPasswordManagerException("Error retrieving credentials", e);
        }
        return credentials;
    }

    @Override
    public Credential getCredentialById(int id, int userId) {
        String sql = "SELECT id, user_id, account_name, username, encrypted_password, url, notes FROM credentials WHERE id = ? AND user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setInt(2, userId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new Credential(rs.getInt("id"), userId, rs.getString("account_name"),
                        rs.getString("username"), rs.getString("encrypted_password"),
                        rs.getString("url"), rs.getString("notes"));
            }
            return null;
        } catch (SQLException e) {
            logger.error("Error retrieving credential by ID: {}", id, e);
            throw new RevPasswordManagerException("Error retrieving credential", e);
        }
    }

    @Override
    public void updateCredential(Credential credential) {
        String sql = "UPDATE credentials SET account_name = ?, username = ?, encrypted_password = ?, url = ?, notes = ? WHERE id = ? AND user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, credential.getAccountName());
            pstmt.setString(2, credential.getUsername());
            pstmt.setString(3, credential.getEncryptedPassword());
            pstmt.setString(4, credential.getUrl());
            pstmt.setString(5, credential.getNotes());
            pstmt.setInt(6, credential.getId());
            pstmt.setInt(7, credential.getUserId());
            pstmt.executeUpdate();
            logger.info("Credential updated with ID: {}", credential.getId());
        } catch (SQLException e) {
            logger.error("Error updating credential", e);
            throw new RevPasswordManagerException("Error updating credential", e);
        }
    }

    @Override
    public void deleteCredential(int id, int userId) {
        String sql = "DELETE FROM credentials WHERE id = ? AND user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.setInt(2, userId);
            pstmt.executeUpdate();
            logger.info("Credential deleted with ID: {}", id);
        } catch (SQLException e) {
            logger.error("Error deleting credential", e);
            throw new RevPasswordManagerException("Error deleting credential", e);
        }
    }

    @Override
    public List<Credential> searchCredentialsByAccountName(int userId, String accountName) {
        List<Credential> credentials = new ArrayList<>();
        String sql = "SELECT id, user_id, account_name, username, encrypted_password, url, notes FROM credentials WHERE user_id = ? AND account_name LIKE ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            pstmt.setString(2, "%" + accountName + "%");
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                credentials.add(new Credential(rs.getInt("id"), userId, rs.getString("account_name"),
                        rs.getString("username"), rs.getString("encrypted_password"),
                        rs.getString("url"), rs.getString("notes")));
            }
        } catch (SQLException e) {
            logger.error("Error searching credentials for user ID: {} with query: {}", userId, accountName, e);
            throw new RevPasswordManagerException("Error searching credentials", e);
        }
        return credentials;
    }
}
