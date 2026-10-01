import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { sendGatewayError } from '../utils/errors.js';

const JWT_SECRET = process.env.JWT_SECRET || 'aegisgate_fallback_deep_signing_secret_key';

interface UserPayload {
    userId: string;
    username: string;
    role: 'admin' | 'developer' | 'user';
    scopes: string[];
}

// Higher-order configuration framework to evaluate specific role access configurations
export const authenticateAndAuthorize = (allowedRoles: string[]) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
            return;
        }

        const token = authHeader.split(' ')[1];

        if (!token) {
            sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
            return;
        }

        try {
            // Cryptographically verify token signature and extract structural data parameters
            const decodedUser = jwt.verify(token, JWT_SECRET) as unknown as UserPayload;

            // Access Evaluation: Enforce Role-Based Access Control boundaries
            if (!allowedRoles.includes(decodedUser.role)) {
                sendGatewayError(res, 403, 'request_blocked', req);
                return;
            }

            // Inject validated user identities directly into the request header streams
            req.headers['x-user-id'] = decodedUser.userId;
            req.headers['x-user-username'] = decodedUser.username;
            req.headers['x-user-role'] = decodedUser.role;

            next();
        } catch (error: any) {
            console.error('[Identity Validation Fault]', error?.message || error);
            // Fail-Closed: If error is an internal database/server error rather than JWT verification error
            if (error?.name !== 'JsonWebTokenError' && error?.name !== 'TokenExpiredError' && error?.name !== 'NotBeforeError') {
                sendGatewayError(res, 503, 'auth_backend_unavailable', req);
                return;
            }

            sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
            return;
        }
    };
};