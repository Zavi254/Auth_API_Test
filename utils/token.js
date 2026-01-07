import crypto from "crypto";

/**
 * Generate secure random token
 */
export function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

/**
 * Generate OAuth state token
 */
export function generateStateToken() {
    return crypto.randomBytes(16).toString("hex");
}