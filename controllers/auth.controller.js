import bcrypt from "bcryptjs";
import { prisma } from "../lib/prisma.js";
import { createSession, setSessionCookie, clearSessionCookie, getSessionToken } from "../utils/session.js";
import { isValidEmail, isValidPassword } from "../utils/validation.js";
import { generateToken } from "../utils/token.js";

/**
 * POST /api/auth/register
 * Register a new user
 */
export async function register(req, res) {
    try {
        const { fullName, email, password } = req.body;

        // Validate required fields
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Validate email format
        if (!isValidEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }

        // Validate password length
        if (!isValidPassword(password)) {
            return res.status(400).json({ message: "Password must be atleast 8 characters" });
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });

        if (existingUser) {
            return res.status(409).json({ message: "User with this email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user and account in transaction
        const result = await prisma.$transaction(async (tx) => {
            // Create user
            const user = await tx.user.create({
                data: {
                    name: fullName,
                    email,
                    emailVerified: false,
                    profile_id: null
                }
            });

            // Create account (credential provider)
            await tx.account.create({
                data: {
                    userId: user.id,
                    providerId: "credential",
                    accountId: user.id,
                    password: hashedPassword
                }
            });

            return user;
        })

        // Create session
        const session = await createSession(result.id, req);

        // Set session cookie
        setSessionCookie(res, session.token);

        return res.status(201).json({
            success: true,
            user: {
                id: result.id,
                email: result.email,
                name: result.name,
                emailVerified: result.emailVerified,
                profile_id: result.profile_id
            }
        });

    } catch (error) {
        console.error("Registration error:", error);
        return res.status(500).json({ message: "Registration failed. Please try again." });
    }
}

/**
 * POST /api/auth/login
 * Login user
 */
export async function login(req, res) {
    try {
        const { email, password } = req.body;

        // Validate required fields
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        // Find user with credential account
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                accounts: {
                    where: { providerId: "credential" }
                },
                profile: true
            }
        });

        // Check if user exists
        if (!user || user.accounts.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Get credential account
        const account = user.accounts[0];

        // Verify password
        const isValidPassword = await bcrypt.compare(password, account.password)

        if (!isValidPassword) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Create new session
        const session = await createSession(user.id, req);

        // Set session cookie
        setSessionCookie(res, session.token);

        return res.status(200).json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                emailVerified: user.emailVerified,
                profile_id: user.profile_id,
                profile: user.profile
            }
        });

    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ message: "Login failed. Please try again." })
    }
}

/**
 * GET /api/auth/session
 * Get current session
 */
export async function getSession(req, res) {
    try {
        // Get session token from cookie
        const sessionToken = getSessionToken(req);

        if (!sessionToken) {
            return res.status(401).json({ message: "No session found" });
        }

        // Find session in database
        const session = await prisma.session.findUnique({
            where: { token: sessionToken },
            include: {
                user: {
                    include: {
                        profile: true
                    }
                }
            }
        });

        // Check if session exists
        if (!session) {
            return res.status(401).json({ message: "Invalid session" });
        }

        // Check if session is expired
        if (session.expiresAt < new Date()) {
            // Delete expired session
            await prisma.session.delete({ where: { token: sessionToken } });

            return res.status(401).json({ message: "Session expired" });
        }

        // Return user data
        return res.status(200).json({
            user: {
                id: session.user.id,
                email: session.user.email,
                name: session.user.name,
                emailVerified: session.user.emailVerified,
                profile_id: session.user.profile_id,
                profile: session.user.profile,
                role: session.user.role,
                image: session.user.image
            }
        });

    } catch (error) {
        console.error("Session validation error:", error);
        return res.status(500).json({ message: "Session validation failed" });
    }
}

/**
 * POST /api/auth/logout
 * Logout user
 */
export async function logout(req, res) {
    try {
        // Get session token from cookie
        const sessionToken = getSessionToken(req);

        if (!sessionToken) {
            return res.status(400).json({ message: "No session found" });
        }

        // Delete session from database
        await prisma.session.delete({
            where: { token: sessionToken }
        }).catch(() => {
            // Ignore errors if sessiond doesn't exist
        });

        // Clear session cookie
        clearSessionCookie(res);

        return res.status(200).json({ success: true, message: "Logged out successfully" })

    } catch (error) {
        console.error("Logout error:", error);
        return res.status(500).json({ message: "Logout failed" });
    }
}

/**
 * POST /api/auth/verify-email
 * Verify email address
 */
export async function verifyEmail(req, res) {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: "Verification token is required" });
        }

        // Find verification token
        const verification = await prisma.verification.findFirst({
            where: {
                value: token,
                expiresAt: {
                    gt: new Date()
                }
            }
        });

        if (!verification) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }

        // Get email from identifier
        const email = verification.identifier;

        // Update user's emailVerified status
        await prisma.user.update({ where: { email }, data: { emailVerified: true } });

        // Delete verification token
        await prisma.verification.delete({ where: { id: verification.id } });

        return res.status(200).json({ success: true, message: "Email verified successfully" });

    } catch (error) {
        console.error("Email verification error:", error);
        return res.status(500).json({ message: "Email verification failed" });
    }
}

/**
 * POST /api/auth/forgot-password
 * Request password reset
 */
export async function forgotPassword(req, res) {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        // Check if user exists
        const user = await prisma.user.findUnique({ where: { email } });

        // Always return success to prevent email enumeration
        if (!user) {
            return res.status(200).json({
                success: true,
                message: "If an account exists, a password reset email will be sent"
            });
        }

        // generate reset token
        const resetToken = generateToken();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiry

        // Save reset token
        await prisma.verification.create({
            data: {
                identifier: email,
                value: resetToken,
                expiresAt
            }
        });

        // TODO: Send password reset email with resetToken
        // await sendPasswordResetEmail(email, resetToken)

        return res.status(200).json({
            success: true,
            message: "If an account exists, a password reset email will be sent",
            // For testing purpose only - remove in production
            ...(process.env.NODE_ENV === "development" && { resetToken })
        });

    } catch (error) {
        console.error("Forgot password error:", error);
        return res.status(500).json({ message: "Failed to process password reset request" });
    }
}

/**
 * POST /api/auth/reset-password
 * Reset password with token
 */
export async function resetPassword(req, res) {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: "Token and new password are required" });
        }

        // Validate password length
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ message: "Password must be at least 8 characters" });
        }

        // Find valid reset token
        const verification = await prisma.verification.findFirst({
            where: {
                value: token,
                expiresAt: {
                    gte: new Date()
                }
            }
        });

        if (!verification) {
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }

        // Get email from identifier
        const email = verification.identifier;

        // Find user
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                accounts: {
                    where: { providerId: "credential" }
                }
            }
        });

        if (!user || user.accounts.length === 0) {
            return res.status(400).json({ message: "User not found" });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await prisma.account.update({
            where: { id: user.accounts[0].id },
            data: { password: hashedPassword }
        });

        // Delete reset token
        await prisma.verification.delete({ where: { id: verification.id } });

        // Delete all existing sessions for security
        await prisma.session.deleteMany({ where: { userId: user.id } })


    } catch (error) {
        console.error("Reset password error:", error);
        return res.status(500).json({ message: "Failed to reset password" });
    }
}