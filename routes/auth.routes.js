import express from "express";
const router = express.Router();

import { register, login, getSession, logout, verifyEmail, forgotPassword, resetPassword } from "../controllers/auth.controller.js";

// Authentication routes
router.post("/register", register);
router.post("/login", login);
router.get("/session", getSession);
router.post("/logout", logout);
router.post("/verify-email", verifyEmail);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

export default router;