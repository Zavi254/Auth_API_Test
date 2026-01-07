/**
 * Validate email format
 */
export function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Validate password length
 */
export function isValidPassword(password) {
    return password && password.length >= 8;
}

/**
 * Validate required fields
 */
export function validateRequiredFields(fields, requiredFields) {
    const missingFields = requiredFields.filter(field => !fields[field]);

    if (missingFields.length > 0) {
        return {
            isValid: false,
            message: `Missing required fields: ${missingFields.join(', ')}`
        };
    }

    return { isValid: true };
}