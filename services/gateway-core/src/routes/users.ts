import { Router } from 'express';
import { authenticateAndAuthorize } from '../middleware/authenticate.js';
import { securityFilter } from '../middleware/securityFilter.js';

const usersRouter = Router();

/**
 * ALL /
 * Handler directly for the /api/v1/users endpoint.
 */
usersRouter.all('/', authenticateAndAuthorize(['admin', 'developer', 'user']), securityFilter, (req, res) => {
    // 1. Process local user array data instantly
    const userData = { status: 'success', data: [] };

    // 2. Instantly return local payload to client
    return res.status(200).json(userData);
});

export { usersRouter };
