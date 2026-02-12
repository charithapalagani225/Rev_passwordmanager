package com.revpasswordmanager.dao;

import com.revpasswordmanager.exception.RevPasswordManagerException;
import com.revpasswordmanager.model.VerificationCode;
import com.revpasswordmanager.util.DatabaseConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;

public class VerificationCodeDaoImpl implements IVerificationCodeDao {
    private static final Logger logger = LogManager.getLogger(VerificationCodeDaoImpl.class);
    private Connection connection;

    public VerificationCodeDaoImpl(Connection connection) {
        this.connection = connection;
    }

    @Override
    public void create(VerificationCode verificationCode) {
        String sql = "INSERT INTO verification_codes (user_id, code, purpose, expiry_time, is_used) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, verificationCode.getUserId());
            pstmt.setString(2, verificationCode.getCode());
            pstmt.setString(3, verificationCode.getPurpose());
            pstmt.setTimestamp(4, verificationCode.getExpiryTime());
            pstmt.setInt(5, verificationCode.isUsed() ? 1 : 0);
            pstmt.executeUpdate();
            logger.info("Verification code created for user ID: {}", verificationCode.getUserId());
        } catch (SQLException e) {
            logger.error("Error creating verification code", e);
            throw new RevPasswordManagerException("Error creating verification code", e);
        }
    }

    @Override
    public VerificationCode getByCodeAndUser(String code, int userId) {
        String sql = "SELECT id, user_id, code, purpose, expiry_time, is_used, created_at FROM verification_codes WHERE code = ? AND user_id = ? AND is_used = 0 AND expiry_time > CURRENT_TIMESTAMP";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, code);
            pstmt.setInt(2, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new VerificationCode(
                            rs.getInt("id"),
                            rs.getInt("user_id"),
                            rs.getString("code"),
                            rs.getString("purpose"),
                            rs.getTimestamp("expiry_time"),
                            rs.getBoolean("is_used"),
                            rs.getTimestamp("created_at"));
                }
            }
            return null;
        } catch (SQLException e) {
            logger.error("Error retrieving verification code", e);
            throw new RevPasswordManagerException("Error retrieving verification code", e);
        }
    }

    @Override
    public void markAsUsed(int id) {
        String sql = "UPDATE verification_codes SET is_used = 1 WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.executeUpdate();
            logger.info("Verification code marked as used with ID: {}", id);
        } catch (SQLException e) {
            logger.error("Error marking verification code as used", e);
            throw new RevPasswordManagerException("Error marking verification code as used", e);
        }
    }

    @Override
    public void cleanupExpired() {
        String sql = "DELETE FROM verification_codes WHERE expiry_time < CURRENT_TIMESTAMP";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.executeUpdate();
            logger.info("Expired verification codes cleaned up");
        } catch (SQLException e) {
            logger.error("Error cleaning up expired verification codes", e);
            throw new RevPasswordManagerException("Error cleaning up expired verification codes", e);
        }
    }
}
