import crypto from "crypto";
import { prisma } from "../lib/prisma.js";

/**
 * Generate secure session token
 */
function generateSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

/**
 * Creates a new session for a user
 * Returns session obect with token
 * Token is sent in response body (not cookie)
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

export { generateSessionToken, createSession }