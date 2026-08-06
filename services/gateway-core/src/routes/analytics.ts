import { Router, type Request, type Response } from 'express';
import mongoose from 'mongoose';
import { ThreatLogModel } from '../models/threatLog.js';
import { DeadLetterModel } from '../models/deadLetter.js';
import { ProjectModel } from '../models/project.js';
import { publishThreatLog } from '../config/queue.js';
import { requireAuth, type AuthRequest } from '../middleware/requireAuth.js';
import { redisClient } from '../config/redis.js';

const analyticsRouter = Router();

/**
 * GET /telemetry
 * Queries live threat logs from MongoDB filtered by project header.
 * Protected by requireAuth middleware. Includes developer ownership checks.
 */
analyticsRouter.get('/telemetry', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const projectId = req.headers['x-project-id'] as string;

        // Prevent CastError exceptions on invalid ObjectIds by verifying format upfront
        if (!projectId || !mongoose.Types.ObjectId.isValid(projectId)) {
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Invalid project identifier or access denied.'
            });
        }

        // Perform strict developer ownership validation
        const project = await ProjectModel.findOne({
            _id: projectId,
            developerId: new mongoose.Types.ObjectId(String(req.user!.userId))
        });

        if (!project) {
            return res.status(403).json({
                error: 'Forbidden',
                message: 'You do not have access rights to this project context.'
            });
        }

        const logs = await ThreatLogModel.find({ projectId })
            .sort({ createdAt: -1 })
            .limit(50);

        const totalBlocks = await ThreatLogModel.countDocuments({ projectId });
        const criticalCount = await ThreatLogModel.countDocuments({ projectId, severity: 'CRITICAL' });
        const highCount = await ThreatLogModel.countDocuments({ projectId, severity: 'HIGH' });

        return res.status(200).json({
            totalBlocks,
            criticalCount,
            highCount,
            logs
        });
    } catch (error: any) {
        console.error('❌ Failed to fetch telemetry statistics:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to retrieve real-time analytics telemetry data.'
        });
    }
});

/**
 * POST /telemetry
 * Ingests external developer threat telemetry records asynchronously.
 */
analyticsRouter.post('/telemetry', async (req: Request, res: Response) => {
    try {
        // Extract the custom Aegis API Key from headers
        const apiKeyHeader = req.headers['x-aegis-api-key'];
        if (!apiKeyHeader || typeof apiKeyHeader !== 'string') {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Missing Aegis API Key header.'
            });
        }

        // Query Redis cache first for API key validation
        let projectId: string | null = null;
        try {
            const cached = await redisClient.get(`project:${apiKeyHeader}`);
            if (cached) {
                const parsed = JSON.parse(cached);
                projectId = parsed.projectId || null;
            }
        } catch (err: any) {
            console.error('[Telemetry Redis Cache Miss Error]:', err.message);
        }

        if (!projectId) {
            const project = await ProjectModel.findOne({ apiKey: apiKeyHeader });
            if (!project) {
                return res.status(401).json({
                    error: 'Unauthorized',
                    message: 'Invalid or revoked Aegis API Key.'
                });
            }
            projectId = String(project._id);
            const cachePayload = JSON.stringify({
                targetUrl: project.targetUrl || process.env.UPSTREAM_TARGET_URL || '',
                dryRun: project.dryRun ?? true,
                enableLLMAudit: project.enableLLMAudit ?? true,
                slackWebhookUrl: project.slackWebhookUrl || '',
                discordWebhookUrl: project.discordWebhookUrl || '',
                projectId,
                projectName: project.projectName
            });
            await redisClient.setex(`project:${apiKeyHeader}`, 300, cachePayload).catch(() => {});
        }

        const telemetryPayload = {
            projectId,
            clientIp: req.body.clientIp || req.ip || req.socket.remoteAddress || 'unknown-client',
            endpoint: req.body.endpoint || '',
            method: req.body.method || 'POST',
            timestamp: req.body.timestamp || new Date().toISOString(),
            rawBody: typeof req.body.rawBody === 'string' ? req.body.rawBody : JSON.stringify(req.body.rawBody || {})
        };

        // Forward enriched payload down system pipeline into RabbitMQ security bus
        await publishThreatLog(telemetryPayload);

        return res.status(202).json({
            success: true,
            message: 'Telemetry packet queued for asynchronous auditing.',
            projectId
        });
    } catch (error: any) {
        console.error('❌ Failed to ingest analytics telemetry:', error.message);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to ingest telemetry payload.'
        });
    }
});

/**
 * GET /dlq
 * Returns dead-lettered poison messages filtered by project header.
 */
analyticsRouter.get('/dlq', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const projectId = req.headers['x-project-id'] as string;
        if (!projectId || !mongoose.Types.ObjectId.isValid(projectId)) {
            return res.status(403).json({ error: 'Forbidden', message: 'Invalid project identifier or access denied.' });
        }

        const project = await ProjectModel.findOne({
            _id: projectId,
            developerId: new mongoose.Types.ObjectId(String(req.user!.userId))
        });

        if (!project) {
            return res.status(403).json({ error: 'Forbidden', message: 'Access denied to this project context.' });
        }

        const logs = await DeadLetterModel.find({ projectId }).sort({ createdAt: -1 }).limit(50);
        return res.status(200).json(logs);
    } catch (error: any) {
        console.error('❌ Failed to fetch DLQ messages:', error.message);
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to retrieve Dead-Letter logs.' });
    }
});

/**
 * POST /dlq/:id/retry
 * Re-queues a poison message back into the primary threat stream and removes it from DLQ.
 */
analyticsRouter.post('/dlq/:id/retry', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const id = String(req.params.id);
        if (!id || !mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Bad Request', message: 'Invalid message ID format.' });
        }

        const doc = await DeadLetterModel.findById(id);
        if (!doc) {
            return res.status(404).json({ error: 'Not Found', message: 'Dead-letter message not found.' });
        }

        await publishThreatLog({
            projectId: doc.projectId,
            clientIp: doc.clientIp,
            endpoint: doc.endpoint,
            method: doc.method,
            timestamp: doc.timestamp.toISOString(),
            rawBody: doc.rawBody
        });

        await DeadLetterModel.findByIdAndDelete(id);

        return res.status(200).json({ success: true, message: 'Message re-queued successfully.' });
    } catch (error: any) {
        console.error('❌ Failed to re-queue DLQ message:', error.message);
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to re-queue dead-letter message.' });
    }
});

/**
 * DELETE /dlq/:id
 * Permanently purges a poison message from the Dead-Letter Queue.
 */
analyticsRouter.delete('/dlq/:id', requireAuth, async (req: AuthRequest, res: Response) => {
    try {
        const id = String(req.params.id);
        if (!id || !mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Bad Request', message: 'Invalid message ID format.' });
        }

        const doc = await DeadLetterModel.findByIdAndDelete(id);
        if (!doc) {
            return res.status(404).json({ error: 'Not Found', message: 'Dead-letter message not found.' });
        }

        return res.status(200).json({ success: true, message: 'Message purged successfully.' });
    } catch (error: any) {
        console.error('❌ Failed to purge DLQ message:', error.message);
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to purge dead-letter message.' });
    }
});

export { analyticsRouter };
