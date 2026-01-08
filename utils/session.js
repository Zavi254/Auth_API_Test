import crypto from "crypto";
import { prisma } from "../lib/prisma.js";

/**
 * Generate secure session token
 */
function generateSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

/**
 * Create a new session for a user
 */
async function createSession(userId, req) {
    const token = generateSessionToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    const ipAddress = req.headers["x-forwarded-for"]
        || req.headers["x-real-ip"] ||
        req.connection.remoteAddress || "unknown";

    const userAgent = req.headers["user-agent"] || "unknown";

    const session = await prisma.session.create({
        data: {
            userId,
            token,
            expiresAt,
            ipAddress,
            userAgent
        }
    });

    return session;
}

/**
 * Set session cookie in response
 */
function setSessionCookie(res, token) {
    const isProduction = process.env.NODE_ENV === "production";

    res.cookie("session", token, {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: "/",
        domain: isProduction ? undefined : undefined
    });
}

/**
 * Clear session cookie
 */
function clearSessionCookie(res) {
    const isProduction = process.env.NODE_ENV === "production"

    res.cookie("session", "", {
        httpOnly: true,
        secure: true,
        sameSite: isProduction ? "none" : "lax",
        maxAge: 0,
        path: "/"
    });
}

/**
 * Get session token from request
 */
function getSessionToken(req) {
    return req.cookies?.session || req.headers.cookie?.match(/session=([^;]+)/)?.[1];
}

export { generateSessionToken, createSession, setSessionCookie, clearSessionCookie, getSessionToken }