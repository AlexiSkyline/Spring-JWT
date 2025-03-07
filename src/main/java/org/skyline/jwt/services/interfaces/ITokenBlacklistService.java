package org.skyline.jwt.services.interfaces;

import jakarta.servlet.http.HttpServletRequest;

public interface ITokenBlacklistService {

    void addToBlacklist(HttpServletRequest request);
    Boolean isBlacklisted(String token);
}
