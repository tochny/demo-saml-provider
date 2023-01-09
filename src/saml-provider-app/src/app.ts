import { generateKeyPairSync } from 'crypto';
import bodyParser from 'body-parser';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Request, Response } from 'express';
import morganBody from 'morgan-body';
import { getMe, logger } from './common';
import { CusError, CusErrorHandler } from './error';
import { authRouter } from './routes/auth';

export const {
  AWS_DEFAULT_REGION,
  DOMAIN_NAME,
  TEST,
  DOCKER,
  ENVIRONMENT_NAME,
} = process.env;

let parameterPath = '';
let whitelist: string[] = [];
if (ENVIRONMENT_NAME === 'develop') {
  parameterPath = '/samlp/dev';
  whitelist = ['https://samlp.dev.yunn.tw', 'http://samlp.local.dev.yunn.tw:3000'];
} else if (ENVIRONMENT_NAME === 'release') {
  parameterPath = '/samlp/beta';
  whitelist = ['https://samlp.beta.yunn.tw', 'http://samlp.local.beta.yunn.tw:3000'];
} else if (ENVIRONMENT_NAME === 'production') {
  parameterPath = '/samlp/prod';
  whitelist = ['https://samlp.yunn.tw', 'http://local.yunn.tw:3000'];
} else { throw new CusError(500, 'Unknown environment', 'Unknown environment'); }

export { parameterPath };

const app = express();
const router = express.Router();

export const corsOptions = {
  optionsSuccessStatus: 200,
  credentials: true,
};

router.use(compression());
app.use(cors({
  origin: (origin, callback) => {
    if (origin && whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else if (!origin) {
      callback(null, true);
    } else {
      callback(new Error());
    }
  },
  ...corsOptions,
}));
app.use(cookieParser());

app.use(bodyParser.json());
morganBody(app, {
  stream: {
    write: (message: unknown) => {
      logger.trace(message);
      return true;
    },
  },
  prettify: false,
  noColors: true,
  logReqDateTime: false,
});

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

if (TEST) {
  logger.level = 'all';
  app.use('/auth', authRouter);
  app.use('/', router);
  app.listen(3000, () => {
    logger.info('STARTED ON 3000');
  });
} else if (DOCKER) {
  logger.level = 'all';
  app.use('/auth', authRouter);
  app.use('/', router);
  app.listen(3000, () => {
    logger.info('STARTED ON 3000 WITH DOCKER');
  });
} else {
  logger.level = 'all';
  app.use('/auth', authRouter);
  app.use('/', router);
}

router.get('/healthcheck', async (req: Request, res: Response) => {
  try {
    return res.status(200).json();
  } catch (error) {
    return res.status(500).json(error);
  }
});

export { app };
