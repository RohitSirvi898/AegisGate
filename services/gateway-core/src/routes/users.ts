import { Router } from 'express';

import { authenticateAndAuthorize } from '../middleware/authenticate.js';
import { securityFilter } from '../middleware/securityFilter.js';

const usersRouter = Router();

usersRouter.all('/', authenticateAndAuthorize(['admin', 'developer', 'user']), securityFilter, (_req, res) => {
  const userData = { status: 'success', data: [] };
  return res.status(200).json(userData);
});

export { usersRouter };
