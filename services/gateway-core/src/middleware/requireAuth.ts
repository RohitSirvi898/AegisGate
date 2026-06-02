import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'aegis_fallback_jwt_secret_key_123';

export interface AuthRequest extends Request {
    user?: {
        userId: string;
    };
}

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Access token is missing or invalid.'
        });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Access token is malformed.'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET as string) as any;
        req.user = { userId: String(decoded.userId) };
        next();
    } catch (err: any) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid, expired, or revoked access token.'
        });
    }
};
