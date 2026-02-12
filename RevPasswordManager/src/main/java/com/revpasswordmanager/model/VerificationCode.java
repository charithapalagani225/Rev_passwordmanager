package com.revpasswordmanager.model;

import java.sql.Timestamp;

public class VerificationCode {
    private int id;
    private int userId;
    private String code;
    private String purpose;
    private Timestamp expiryTime;
    private boolean isUsed;
    private Timestamp createdAt;

    public VerificationCode() {
    }

    public VerificationCode(int id, int userId, String code, String purpose, Timestamp expiryTime, boolean isUsed,
            Timestamp createdAt) {
        this.id = id;
        this.userId = userId;
        this.code = code;
        this.purpose = purpose;
        this.expiryTime = expiryTime;
        this.isUsed = isUsed;
        this.createdAt = createdAt;
    }

    public VerificationCode(int userId, String code, String purpose, Timestamp expiryTime) {
        this.userId = userId;
        this.code = code;
        this.purpose = purpose;
        this.expiryTime = expiryTime;
        this.isUsed = false;
        this.createdAt = new Timestamp(System.currentTimeMillis());
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public Timestamp getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(Timestamp expiryTime) {
        this.expiryTime = expiryTime;
    }

    public boolean isUsed() {
        return isUsed;
    }

    public void setUsed(boolean used) {
        isUsed = used;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "VerificationCode{" +
                "id=" + id +
                ", userId=" + userId +
                ", code='" + code + '\'' +
                ", purpose='" + purpose + '\'' +
                ", expiryTime=" + expiryTime +
                ", isUsed=" + isUsed +
                ", createdAt=" + createdAt +
                '}';
    }
}
