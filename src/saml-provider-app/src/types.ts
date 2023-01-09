import { Request } from 'express';

export interface PaginationPayload<T> {
  totalPage: number;
  list: T[];
}

export interface PaginationParameters {
  limit: number;
  page: number;
}

export interface TypedRequestBody<T> extends Request {
  body: T;
}

export enum PayloadType {
  EMAIL,
  ROLE,
  UUID,
  AWS_ACCESSKEY,
  AWS_SECRETKEY,
  OTHER,
}

export interface ICusError extends Error {
  /**
   * A unique short code representing the error that was emitted.
   */
  code?: string;
  /**
   * A longer human readable error message.
   */
  message: string;
  /**
   * Whether the error message is retryable.
   */
  retryable?: boolean;
  /**
   * In the case of a request that reached the service, this value contains the response status code.
   */
  statusCode?: number;
  /**
   * The date time object when the error occurred.
   */
  time?: Date;
  /**
   * Set when a networking error occurs to easily identify the endpoint of the request.
   */
  hostname?: string;
  /**
   * Set when a networking error occurs to easily identify the region of the request.
   */
  region?: string;
  /**
   * Amount of time (in seconds) that the request waited before being resent.
   */
  retryDelay?: number;
  /**
   * The unique request ID associated with the response.
   */
  requestId?: string;
  /**
   * Second request ID associated with the response from S3.
   */
  extendedRequestId?: string;
  /**
   * CloudFront request ID associated with the response.
   */
  cfId?: string;
  /**
   * The original error which caused this Error
   */
  originalError?: Error;
}

export type DigestAlgorithmType = 'sha1' | 'sha256';
export type SignatureAlgorithmType = 'rsa-sha1' | 'rsa-sha256';

export interface IdPOptions {
  issuer: string;
  cert: string | Buffer;
  key: string | Buffer;
  audience?: string | undefined;
  recipient?: string | undefined;
  destination?: string | undefined;
  RelayState?: string | undefined;
  digestAlgorithm?: DigestAlgorithmType | undefined;
  signatureAlgorithm?: SignatureAlgorithmType | undefined;
  signResponse?: boolean | undefined;
  encryptionCert?: string | Buffer | undefined;
  encryptionPublicKey?: string | Buffer | undefined;
  encryptionAlgorithm?: string | undefined;
  keyEncryptionAlgorighm?: string | undefined;
  lifetimeInSeconds?: number | undefined;
  authnContextClassRef?: string | undefined;
  inResponseTo?: string | undefined;
}
