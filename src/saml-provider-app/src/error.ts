import { NextFunction, Request, Response } from 'express';
import { logger } from './common';
import { ICusError } from './types';

export class CusError extends Error implements ICusError {
  message: string;

  code: string;

  statusCode: number;

  constructor(statusCode: number, code: string, message: string) {
    super(code);
    this.message = message;
    this.code = code;
    this.statusCode = statusCode;
  }
}

export async function CusErrorHandler(err: ICusError, req: Request, res: Response, next?: NextFunction) {
  logger.error(err);
  return res.status(err.statusCode ?? 500).json({
    message: err.message,
    error: err.code,
  });
}
