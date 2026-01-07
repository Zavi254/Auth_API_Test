import cors from "cors";

export function configureCors() {
    return cors({
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        credentials: true
    });
}