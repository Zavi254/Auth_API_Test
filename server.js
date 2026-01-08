import "dotenv/config";
import express from "express";
import { configureCors } from "./config/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import authRoutes from "./routes/auth.routes.js";
import { prisma } from "./lib/prisma.js";

const app = express();

// Middleware
app.use(express.json());
app.use(configureCors());

// Debug middleware to check response headers
app.use((req, res, next) => {
    const originalJson = res.json();
    res.json = function (data) {
        console.log("Response Headers:", res.getHeaders());
        return originalJson.call(this, data);
    }
    next();
})

// Routes
app.use("/api/auth", authRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        timestamp: new Date().toISOString()
    });
})

// Error handling middleware (must be last)
app.use(errorHandler);

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
    console.log(`Auth API server running on port ${PORT}`);
    console.log(`Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
    console.log(`Auth API URL: ${process.env.AUTH_API_URL || `http://localhost:${PORT}`}`);
});

// Graceful shutdown
process.on("SIGTERM", async () => {
    console.log("SIGTERM received, closing server...");
    await prisma.$disconnect();
    process.exit(0);
})

process.on("SIGINT", async () => {
    console.log("SIGINT received, closing server...");
    await prisma.$disconnect();
    process.exit(0);
})