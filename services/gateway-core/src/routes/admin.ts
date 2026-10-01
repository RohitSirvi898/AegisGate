import { Router, type Request, type Response } from 'express';
import { getJailedIps, unbanIp } from '../middleware/ipJail.js';
import { getAllCircuitBreakers } from '../middleware/circuitBreaker.js';

const adminRouter = Router();

/**
 * GET /api/v1/admin/jailed-ips or /api/v1/admin/jail
 * Returns list of currently jailed client IPs with remaining TTLs.
 */
adminRouter.get(['/jailed-ips', '/jail'], async (_req: Request, res: Response) => {
    try {
        const jailedIps = await getJailedIps();
        return res.status(200).json({
            success: true,
            jailedIps
        });
    } catch (err: any) {
        console.error('❌ Failed to retrieve jailed IPs:', err?.message || err);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to retrieve jailed IP addresses.'
        });
    }
});

/**
 * POST /api/v1/admin/unban
 * Unbans a specified client IP by purging jail and abuse counter keys from Redis.
 */
adminRouter.post('/unban', async (req: Request, res: Response) => {
    try {
        const ip = req.body?.ip || req.body?.clientIp;
        if (!ip || typeof ip !== 'string') {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Field "ip" is required and must be a valid string.'
            });
        }

        const success = await unbanIp(ip.trim());
        return res.status(200).json({
            success,
            message: success ? `Client IP ${ip} successfully unbanned.` : `Client IP ${ip} was not in jail.`
        });
    } catch (err: any) {
        console.error('❌ Failed to unban IP:', err?.message || err);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to unban IP address.'
        });
    }
});

/**
 * DELETE /api/v1/admin/jail/:ip
 * RESTful alternative to unban a specified client IP.
 */
adminRouter.delete('/jail/:ip', async (req: Request, res: Response) => {
    try {
        const rawIp = req.params.ip;
        const ip = Array.isArray(rawIp) ? rawIp[0] : rawIp;
        if (!ip) {
            return res.status(400).json({
                error: 'Bad Request',
                message: 'IP parameter is required.'
            });
        }

        const success = await unbanIp(ip.trim());
        return res.status(200).json({
            success,
            message: success ? `Client IP ${ip} successfully unbanned.` : `Client IP ${ip} was not in jail.`
        });
    } catch (err: any) {
        console.error('❌ Failed to unban IP:', err?.message || err);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to unban IP address.'
        });
    }
});

/**
 * GET /api/v1/admin/circuit-breakers
 * Returns active circuit breaker state machines and health for all upstream origins.
 */
adminRouter.get('/circuit-breakers', async (_req: Request, res: Response) => {
    try {
        const breakers = getAllCircuitBreakers();
        return res.status(200).json({
            success: true,
            circuitBreakers: breakers
        });
    } catch (err: any) {
        console.error('❌ Failed to retrieve circuit breaker status:', err?.message || err);
        return res.status(500).json({
            error: 'Internal Server Error',
            message: 'Failed to retrieve circuit breaker metrics.'
        });
    }
});

export { adminRouter };
