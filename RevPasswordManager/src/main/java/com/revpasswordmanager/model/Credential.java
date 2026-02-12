package com.revpasswordmanager.model;

public class Credential {
    private int id;
    private int userId;
    private String accountName;
    private String username;
    private String encryptedPassword;
    private String url;
    private String notes;

    public Credential(int userId, String accountName, String username, String encryptedPassword, String url,
            String notes) {
        this.userId = userId;
        this.accountName = accountName;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        this.url = url;
        this.notes = notes;
    }

    public Credential(int id, int userId, String accountName, String username, String encryptedPassword, String url,
            String notes) {
        this.id = id;
        this.userId = userId;
        this.accountName = accountName;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        this.url = url;
        this.notes = notes;
    }

    // Getters
    public int getId() {
        return id;
    }

    public int getUserId() {
        return userId;
    }

    public String getAccountName() {
        return accountName;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getUrl() {
        return url;
    }

    public String getNotes() {
        return notes;
    }

    // Setters
    public void setId(int id) {
        this.id = id;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public void setAccountName(String accountName) {
        this.accountName = accountName;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}
