import { Router, type Response } from 'express';
import mongoose from 'mongoose';
import crypto from 'crypto';
import { requireAuth, type AuthRequest } from '../middleware/requireAuth.js';
import { ProjectModel } from '../models/project.js';

const projectsRouter = Router();

/**
 * POST /
 * Endpoint to register a new project and generate secure API keys.
 * Protected by requireAuth middleware.
 */
projectsRouter.post('/', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const { projectName } = req.body;
        if (!projectName || typeof projectName !== 'string' || projectName.trim() === '') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Project name is required and must be a valid non-empty string.'
            });
        }

        // Generate a secure random token prefixed with ag_live_ using crypto
        const apiKey = `ag_live_${crypto.randomBytes(24).toString('hex')}`;
        
        const newProject = new ProjectModel({
            projectName: projectName.trim(),
            developerId: new mongoose.Types.ObjectId(req.user!.userId), // Set from the authenticated token
            apiKey
        });

        await newProject.save();

        return res.status(201).json(newProject);
    } catch (error: any) {
        console.error('❌ Failed to provision project:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to provision a new project and secure API key.'
        });
    }
});

/**
 * GET /
 * Returns all projects where developerId matches the authenticated userId.
 * Protected by requireAuth middleware.
 */
projectsRouter.get('/', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const userId = new mongoose.Types.ObjectId(req.user!.userId);
        const projects = await ProjectModel.find({ developerId: userId });
        return res.status(200).json(projects);
    } catch (error: any) {
        console.error('❌ Failed to fetch user projects:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to retrieve projects list.'
        });
    }
});

export { projectsRouter };

