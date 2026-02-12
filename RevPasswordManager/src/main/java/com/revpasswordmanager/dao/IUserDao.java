package com.revpasswordmanager.dao;

import com.revpasswordmanager.model.SecurityQuestion;
import com.revpasswordmanager.model.User;

import java.util.List;

public interface IUserDao {
    void createUser(User user);

    User getUserByUsername(String username);

    void updateUser(User user);

    void addSecurityQuestion(SecurityQuestion sq);

    List<SecurityQuestion> getSecurityQuestionsByUserId(int userId);

    void updateSecurityQuestion(SecurityQuestion sq);

    void deleteSecurityQuestion(int id);

    SecurityQuestion getSecurityQuestionById(int id);
}
