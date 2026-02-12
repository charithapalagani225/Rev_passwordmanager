package com.revpasswordmanager.util;

import java.io.Console;
import java.util.Scanner;

public class ConsoleUtil {
    private static Console console = System.console();

    public static String getPasswordInput(Scanner scanner, String prompt) {
        if (console != null) {
            return new String(console.readPassword(prompt));
        } else {
            System.out.print(prompt);
            return scanner.nextLine();
        }
    }

    public static int getIntInput(Scanner scanner) {
        String line = scanner.nextLine();
        if (line == null || line.trim().isEmpty())
            return -1;
        try {
            return Integer.parseInt(line.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public static int getIntInput(Scanner scanner, String prompt) {
        System.out.print(prompt);
        return getIntInput(scanner);
    }

    public static String getStringInput(Scanner scanner, String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    public static boolean getBooleanInput(Scanner scanner, String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().equalsIgnoreCase("y");
    }
}
