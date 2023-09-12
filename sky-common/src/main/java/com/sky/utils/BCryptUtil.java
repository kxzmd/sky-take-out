package com.sky.utils;

import org.mindrot.jbcrypt.BCrypt;

public class BCryptUtil {
    private static final int WORK_FACTOR = 12;

    // 加密密码
    public static String encryptPassword(String password) {
        String salt = BCrypt.gensalt(WORK_FACTOR);
        return BCrypt.hashpw(password, salt);
    }

    // 验证密码
    public static boolean checkPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

}
