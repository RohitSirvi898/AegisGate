import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

import { sendGatewayError } from '../utils/errors.js';

const JWT_SECRET = process.env.JWT_SECRET || 'aegis_fallback_jwt_secret_key_123';

export interface AuthRequest extends Request {
  user?: {
    userId: string;
  };
}

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
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
    const decoded = jwt.verify(token, JWT_SECRET as string) as any;
    req.user = { userId: String(decoded.userId) };
    next();
  } catch (err: any) {
    console.error('[JWT Auth Error]:', err?.message || err);
    if (err?.name !== 'JsonWebTokenError' && err?.name !== 'TokenExpiredError' && err?.name !== 'NotBeforeError') {
      sendGatewayError(res, 503, 'auth_backend_unavailable', req);
      return;
    }
    sendGatewayError(res, 401, 'invalid_or_missing_credentials', req);
    return;
  }
};
