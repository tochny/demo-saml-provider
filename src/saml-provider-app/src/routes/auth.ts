import compression from 'compression';
import express, { Request, Response } from 'express';
import { parameterPath } from '../app';
import { getParameterStoreValue } from '../common';
import { CusError, CusErrorHandler } from '../error';
import { getSamlMetadata, getSamlResponse } from '../saml';

const authRouter = express.Router();

authRouter.use(compression());
authRouter.use(express.json());
authRouter.use(express.urlencoded({ extended: true }));

authRouter.get('/samlp/FederationMetadata/2007-06/FederationMetadata.xml', async (req: Request, res: Response) => {
  try {
    res.send((await getSamlMetadata()).replace(/\n(?:\s*\n)+/g, '\n'));
  } catch (error) {
    await CusErrorHandler(error, req, res);
  }
});

authRouter.get('/samlp/login', async (req: Request, res: Response) => {
  try {
    const { platformId, nameId, authToken } = req.query;
    if (!platformId || !nameId || !authToken) { throw new CusError(400, 'Missing required query parameters', 'Missing required query parameters: platformId, nameId, authToken'); }

    if (authToken !== await getParameterStoreValue(`${parameterPath}/SamlAuthToken`)) { throw new CusError(401, 'Invalid auth token', 'Invalid auth token'); }

    return res.send(encodeURIComponent(await getSamlResponse(platformId as string, nameId as string)));
  } catch (error) {
    await CusErrorHandler(error, req, res);
  }
});

export { authRouter };
