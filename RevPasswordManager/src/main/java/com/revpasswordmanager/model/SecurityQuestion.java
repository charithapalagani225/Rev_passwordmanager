package com.revpasswordmanager.model;

public class SecurityQuestion {
    private int id;
    private int userId;
    private String question;
    private String answerHash;

    public SecurityQuestion(int userId, String question, String answerHash) {
        this.userId = userId;
        this.question = question;
        this.answerHash = answerHash;
    }

    public int getId() {
        return id;
    }

    public int getUserId() {
        return userId;
    }

    public String getQuestion() {
        return question;
    }

    public String getAnswerHash() {
        return answerHash;
    }


    public void setId(int id) {
        this.id = id;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public void setAnswerHash(String answerHash) {
        this.answerHash = answerHash;
    }
}
