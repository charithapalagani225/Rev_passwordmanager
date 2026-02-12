package com.revpasswordmanager.service;

import com.revpasswordmanager.dao.IVerificationCodeDao;
import com.revpasswordmanager.dao.VerificationCodeDaoImpl;
import com.revpasswordmanager.model.VerificationCode;
import com.revpasswordmanager.util.DatabaseConnection;

import com.revpasswordmanager.exception.RevPasswordManagerException;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.Timestamp;

public class OTPServiceImpl implements IOTPService {
    private static final int OTP_LENGTH = 6;
    private static final long OTP_VALIDITY_MS = 5 * 60 * 1000L; // 5 minutes
    private SecureRandom random = new SecureRandom();

    @Override
    public String generateOTP(int userId, String purpose) {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }

        Timestamp expiryTime = new Timestamp(System.currentTimeMillis() + OTP_VALIDITY_MS);
        VerificationCode code = new VerificationCode(userId, otp.toString(), purpose, expiryTime);

        Connection connection = DatabaseConnection.getConnection();
        try {
            IVerificationCodeDao dao = new VerificationCodeDaoImpl(connection);
            dao.create(code);
            return otp.toString();
        } catch (RevPasswordManagerException e) {
            e.printStackTrace(); // Consider using Logger here if available, but for now matching existing style
                                 // + pattern
            return null;
        }
    }

    @Override
    public boolean validateOTP(int userId, String code, String purpose) {
        Connection connection = DatabaseConnection.getConnection();
        try {
            IVerificationCodeDao dao = new VerificationCodeDaoImpl(connection);
            VerificationCode validCode = dao.getByCodeAndUser(code, userId);

            if (validCode != null && validCode.getPurpose().equals(purpose)) {
                dao.markAsUsed(validCode.getId());
                return true;
            }
        } catch (RevPasswordManagerException e) {
            e.printStackTrace();
        }
        return false;
    }
}
