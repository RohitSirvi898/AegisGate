import { Router, type Response } from 'express';
import mongoose from 'mongoose';
import crypto from 'crypto';
import { requireAuth, type AuthRequest } from '../middleware/requireAuth.js';
import { ProjectModel } from '../models/project.js';
import { redisClient } from '../config/redis.js';

const projectsRouter = Router();

/**
 * Validates if a string is a valid HTTP/HTTPS URL or empty string.
 */
const isValidWebhookUrl = (url?: string): boolean => {
    if (!url || url.trim() === '') return true;
    try {
        const parsed = new URL(url.trim());
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
};

/**
 * POST /
 * Endpoint to register a new project and generate secure API keys.
 * Protected by requireAuth middleware.
 */
projectsRouter.post('/', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const { targetUrl, dryRun, enableLLMAudit, slackWebhookUrl, discordWebhookUrl } = req.body;
        const nameInput = req.body.projectName || req.body.name;

        if (!nameInput || typeof nameInput !== 'string' || nameInput.trim() === '') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Project name is required and must be a valid non-empty string.'
            });
        }

        if (!isValidWebhookUrl(slackWebhookUrl) || !isValidWebhookUrl(discordWebhookUrl)) {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Invalid Slack or Discord Webhook URL format.'
            });
        }

        // Generate a secure random token prefixed with ag_live_ using crypto
        const apiKey = `ag_live_${crypto.randomBytes(24).toString('hex')}`;
        
        const newProject = new ProjectModel({
            projectName: nameInput.trim(),
            developerId: new mongoose.Types.ObjectId(String(req.user!.userId)), // Set from the authenticated token
            apiKey,
            targetUrl: typeof targetUrl === 'string' ? targetUrl.trim() : '',
            dryRun: typeof dryRun === 'boolean' ? dryRun : true,
            enableLLMAudit: typeof enableLLMAudit === 'boolean' ? enableLLMAudit : true,
            slackWebhookUrl: typeof slackWebhookUrl === 'string' ? slackWebhookUrl.trim() : '',
            discordWebhookUrl: typeof discordWebhookUrl === 'string' ? discordWebhookUrl.trim() : ''
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
 * PUT /:id
 * Updates an existing project's settings including Webhook URLs.
 */
projectsRouter.put('/:id', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        if (!id || typeof id !== 'string' || !mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Bad Request', message: 'Invalid project ID format.' });
        }

        const { targetUrl, dryRun, enableLLMAudit, slackWebhookUrl, discordWebhookUrl } = req.body;
        const nameInput = req.body.projectName || req.body.name;

        if (slackWebhookUrl !== undefined && !isValidWebhookUrl(slackWebhookUrl)) {
            return res.status(400).json({ error: 'Bad Request', message: 'Invalid Slack Webhook URL format.' });
        }

        if (discordWebhookUrl !== undefined && !isValidWebhookUrl(discordWebhookUrl)) {
            return res.status(400).json({ error: 'Bad Request', message: 'Invalid Discord Webhook URL format.' });
        }

        const project = await ProjectModel.findOne({
            _id: id,
            developerId: new mongoose.Types.ObjectId(String(req.user!.userId))
        });

        if (!project) {
            return res.status(404).json({ error: 'Not Found', message: 'Project not found or access denied.' });
        }

        if (typeof nameInput === 'string' && nameInput.trim() !== '') {
            project.projectName = nameInput.trim();
        }
        if (typeof targetUrl === 'string') {
            project.targetUrl = targetUrl.trim();
        }
        if (typeof dryRun === 'boolean') {
            project.dryRun = dryRun;
        }
        if (typeof enableLLMAudit === 'boolean') {
            project.enableLLMAudit = enableLLMAudit;
        }
        if (typeof slackWebhookUrl === 'string') {
            project.slackWebhookUrl = slackWebhookUrl.trim();
        }
        if (typeof discordWebhookUrl === 'string') {
            project.discordWebhookUrl = discordWebhookUrl.trim();
        }

        await project.save();

        // Invalidate cached Redis mapping for immediate real-time policy enforcement
        try {
            await redisClient.del(`project:${project.apiKey}`);
        } catch (redisErr: any) {
            console.error('[Redis Cache Invalidation Error]:', redisErr.message);
        }

        return res.status(200).json(project);
    } catch (error: any) {
        console.error('❌ Failed to update project:', error.message);
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to update project settings.' });
    }
});

/**
 * GET /
 * Returns all projects where developerId matches the authenticated userId.
 * Protected by requireAuth middleware.
 */
projectsRouter.get('/', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const userId = new mongoose.Types.ObjectId(String(req.user!.userId));
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
