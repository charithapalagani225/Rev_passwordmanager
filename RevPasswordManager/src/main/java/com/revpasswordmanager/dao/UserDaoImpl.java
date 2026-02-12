package com.revpasswordmanager.dao;

import com.revpasswordmanager.exception.RevPasswordManagerException;
import com.revpasswordmanager.exception.UserAlreadyExistsException;
import com.revpasswordmanager.model.SecurityQuestion;
import com.revpasswordmanager.model.User;
import com.revpasswordmanager.util.DatabaseConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class UserDaoImpl implements IUserDao {

    private static final Logger logger = LogManager.getLogger(UserDaoImpl.class);
    private Connection connection;

    public UserDaoImpl(Connection connection) {
        this.connection = connection;
    }

    public void createUser(User user) {
        String sql = "INSERT INTO users (username, master_password_hash, name, email) VALUES (?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, user.getUsername());
            pstmt.setString(2, user.getMasterPasswordHash());
            pstmt.setString(3, user.getName());
            pstmt.setString(4, user.getEmail());
            pstmt.executeUpdate();
            logger.info("User created successfully: {}", user.getUsername());
        } catch (SQLException e) {
            logger.error("Error creating user: {}", user.getUsername(), e);
            if (e.getMessage().contains("link failure")) { // Basic check, ideally check specific SQLState/vendor code
                throw new RevPasswordManagerException("Database connection error", e);
            }
            // Assuming integrity constraint violation for now, or we could check SQLState
            // 23000
            throw new UserAlreadyExistsException("User already exists: " + user.getUsername());
        }
    }

    public User getUserByUsername(String username) {
        String sql = "SELECT id, username, master_password_hash, name, email FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new User(rs.getInt("id"), username, rs.getString("master_password_hash"),
                        rs.getString("name"), rs.getString("email"));
            }
            return null;
        } catch (SQLException e) {
            logger.error("Error retrieving user by username: {}", username, e);
            throw new RevPasswordManagerException("Error retrieving user", e);
        }
    }

    public void updateUser(User user) {
        String sql = "UPDATE users SET master_password_hash = ?, name = ?, email = ? WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, user.getMasterPasswordHash());
            pstmt.setString(2, user.getName());
            pstmt.setString(3, user.getEmail());
            pstmt.setInt(4, user.getId());
            pstmt.executeUpdate();
            logger.info("User updated successfully: {}", user.getUsername());
        } catch (SQLException e) {
            logger.error("Error updating user: {}", user.getUsername(), e);
            throw new RevPasswordManagerException("Error updating user", e);
        }
    }

    public void addSecurityQuestion(SecurityQuestion sq) {
        String sql = "INSERT INTO security_questions (user_id, question, answer_hash) VALUES (?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, sq.getUserId());
            pstmt.setString(2, sq.getQuestion());
            pstmt.setString(3, sq.getAnswerHash());
            pstmt.executeUpdate();
            logger.info("Security question added for user ID: {}", sq.getUserId());
        } catch (SQLException e) {
            logger.error("Error adding security question", e);
            throw new RevPasswordManagerException("Error adding security question", e);
        }
    }

    public List<SecurityQuestion> getSecurityQuestionsByUserId(int userId) {
        List<SecurityQuestion> questions = new ArrayList<>();
        String sql = "SELECT id, user_id, question, answer_hash FROM security_questions WHERE user_id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                SecurityQuestion q = new SecurityQuestion(userId, rs.getString("question"),
                        rs.getString("answer_hash"));
                q.setId(rs.getInt("id"));
                questions.add(q);
            }
        } catch (SQLException e) {
            logger.error("Error retrieving security questions for user ID: {}", userId, e);
            throw new RevPasswordManagerException("Error retrieving security questions", e);
        }
        return questions;
    }

    public void updateSecurityQuestion(SecurityQuestion sq) {
        String sql = "UPDATE security_questions SET question = ?, answer_hash = ? WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, sq.getQuestion());
            pstmt.setString(2, sq.getAnswerHash());
            pstmt.setInt(3, sq.getId());
            pstmt.executeUpdate();
            logger.info("Security question updated with ID: {}", sq.getId());
        } catch (SQLException e) {
            logger.error("Error updating security question", e);
            throw new RevPasswordManagerException("Error updating security question", e);
        }
    }

    public void deleteSecurityQuestion(int id) {
        String sql = "DELETE FROM security_questions WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            pstmt.executeUpdate();
            logger.info("Security question deleted with ID: {}", id);
        } catch (SQLException e) {
            logger.error("Error deleting security question", e);
            throw new RevPasswordManagerException("Error deleting security question", e);
        }
    }

    public SecurityQuestion getSecurityQuestionById(int id) {
        String sql = "SELECT id, user_id, question, answer_hash FROM security_questions WHERE id = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, id);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                SecurityQuestion q = new SecurityQuestion(rs.getInt("user_id"), rs.getString("question"),
                        rs.getString("answer_hash"));
                q.setId(rs.getInt("id"));
                return q;
            }
            return null;
        } catch (SQLException e) {
            logger.error("Error retrieving security question by ID: {}", id, e);
            throw new RevPasswordManagerException("Error retrieving security question", e);
        }
    }
}
