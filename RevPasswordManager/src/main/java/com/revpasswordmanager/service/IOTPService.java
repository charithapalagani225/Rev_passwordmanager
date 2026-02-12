package com.revpasswordmanager.service;

public interface IOTPService {
    String generateOTP(int userId, String purpose);

    boolean validateOTP(int userId, String code, String purpose);
}
