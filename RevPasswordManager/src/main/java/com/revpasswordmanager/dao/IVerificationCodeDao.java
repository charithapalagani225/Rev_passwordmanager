package com.revpasswordmanager.dao;

import com.revpasswordmanager.model.VerificationCode;

public interface IVerificationCodeDao {
    void create(VerificationCode verificationCode);

    VerificationCode getByCodeAndUser(String code, int userId);

    void markAsUsed(int id);

    void cleanupExpired();
}
