import { Router, type Request, type Response } from 'express';
import mongoose from 'mongoose';
import { ThreatLogModel } from '../models/threatLog.js';
import { ProjectModel } from '../models/project.js';
import { publishThreatLog } from '../config/queue.js';
import { requireAuth, type AuthRequest } from '../middleware/requireAuth.js';

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
            developerId: req.user!.userId
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

        // Query Project collection using Mongoose Project model to validate the key
        const project = await ProjectModel.findOne({ apiKey: apiKeyHeader });
        if (!project) {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'Invalid or revoked Aegis API Key.'
            });
        }

        // Extract internal database project ID and stamp payload
        const projectId = String(project._id);

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

export { analyticsRouter };
