import { Router, type Request, type Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { UserModel } from '../models/User.js';

const authRouter = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'aegis_fallback_jwt_secret_key_123';

/**
 * POST /register
 * Registers a new user developer and returns a signed JWT token.
 */
authRouter.post('/register', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Email and password are required and must be valid strings.'
            });
        }

        const trimmedEmail = email.trim().toLowerCase();

        // Check if user already exists
        const existingUser = await UserModel.findOne({ email: trimmedEmail });
        if (existingUser) {
            return res.status(409).json({
                error: 'Conflict',
                message: 'A user with this email address already exists.'
            });
        }

        // Hash the password with bcryptjs (salt rounds 10)
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new UserModel({
            email: trimmedEmail,
            password: hashedPassword
        });

        await newUser.save();

        // Sign stateless JWT containing userId
        const token = jwt.sign({ userId: String(newUser._id) }, JWT_SECRET, { expiresIn: '24h' });

        // Store the token in the response headers and expose them for client access
        res.setHeader('Authorization', `Bearer ${token}`);
        res.setHeader('x-auth-token', token);
        res.setHeader('Access-Control-Expose-Headers', 'Authorization, x-auth-token');

        return res.status(201)
            .cookie('x-auth-token', token, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            })
            .json({
                success: true,
                message: 'User registered successfully.',
                token
            });
    } catch (err: any) {
        console.error('❌ Registration Failure:', err.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to register new user.'
        });
    }
});

/**
 * POST /login
 * Authenticates credentials and returns a signed JWT token.
 */
authRouter.post('/login', async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Email and password are required and must be valid strings.'
            });
        }

        const trimmedEmail = email.trim().toLowerCase();

        const user = await UserModel.findOne({ email: trimmedEmail });
        if (!user || !user.password) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid email or password.'
            });
        }

        // Compare password via bcryptjs
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid email or password.'
            });
        }

        // Sign stateless JWT containing userId
        const token = jwt.sign({ userId: String(user._id) }, JWT_SECRET, { expiresIn: '24h' });

        // Store the token in the response headers and expose them for client access
        res.setHeader('Authorization', `Bearer ${token}`);
        res.setHeader('x-auth-token', token);
        res.setHeader('Access-Control-Expose-Headers', 'Authorization, x-auth-token');

        return res.status(200)
            .cookie('x-auth-token', token, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            })
            .json({
                success: true,
                message: 'User logged in successfully.',
                token
            });
    } catch (err: any) {
        console.error('❌ Login Failure:', err.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to authenticate user.'
        });
    }
});

export { authRouter };
