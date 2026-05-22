import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

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
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Missing or structurally invalid Authentication token strings.',
                timestamp: new Date().toISOString()
            });
            return;
        }

        const token = authHeader.split(' ')[1];

        if (!token) {
            res.status(401).json({
                error: 'Unauthorized',
                message: 'Missing or structurally invalid Authentication token strings.',
                timestamp: new Date().toISOString()
            });
            return;
        }

        try {
            // Cryptographically verify token signature and extract structural data parameters
            const decodedUser = jwt.verify(token, JWT_SECRET) as unknown as UserPayload;

            // Access Evaluation: Enforce Role-Based Access Control boundaries
            if (!allowedRoles.includes(decodedUser.role)) {
                res.status(403).json({
                    error: 'Forbidden',
                    message: 'Access Denied: Your assigned identity role lacks authorization rights for this domain profile.',
                    timestamp: new Date().toISOString()
                });
                return;
            }

            // Inject validated user identities directly into the request header streams
            // This allows internal downstream services to completely trust identity telemetry without re-verifying crypto tokens
            req.headers['x-user-id'] = decodedUser.userId;
            req.headers['x-user-username'] = decodedUser.username;
            req.headers['x-user-role'] = decodedUser.role;

            next();
        } catch (error: any) {
            console.error('[Identity Validation Fault]', error.message);
            res.status(401).json({
                error: 'Unauthorized',
                message: 'The provided access credential validation signature has expired or is cryptographically invalid.',
                timestamp: new Date().toISOString()
            });
            return;
        }
    };
};