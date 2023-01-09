import { generateKeyPairSync } from 'crypto';
import AWS from 'aws-sdk';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import * as log4js from 'log4js';
import { AWS_DEFAULT_REGION, parameterPath } from './app';
import { paramStore, secretsManager, kms, dynamoDB, } from './awsapi';
import { CusError } from './error';
import { getSamlResponse } from './saml';
import { CognitoUserPayload, PayloadType, AwsCredential, } from './types';

log4js.configure({
  appenders: { api: { type: 'console', layout: { type: 'basic' } } },
  categories: { default: { appenders: ['api'], level: 'info' } },
});

export const logger = log4js.getLogger('api');

export async function getSecretValue(SecretId: string) {
  const secretValue = await secretsManager.getSecretValue({ SecretId }).promise();
  if (secretValue.SecretString) { return JSON.parse(secretValue.SecretString); }
}

export async function getParameterStoreValue(name: string) {
  const params = {
    Name: name,
    WithDecryption: true,
  };
  const result = await paramStore.getParameter(params).promise();
  return result.Parameter?.Value;
}

export async function kmsDecrypt(keyId: AWS.KMS.KeyIdType, cipherTextBlob: AWS.KMS.CiphertextType) {
  const params: AWS.KMS.DecryptRequest = {
    CiphertextBlob: cipherTextBlob,
    KeyId: keyId,
  };
  const result = await kms.decrypt(params).promise();
  return result.Plaintext;
}

export async function kmsEncrypt(keyId: AWS.KMS.KeyIdType, plainText: AWS.KMS.CiphertextType) {
  const params: AWS.KMS.EncryptRequest = {
    Plaintext: plainText,
    KeyId: keyId,
  };
  const result = await kms.encrypt(params).promise();
  return result.CiphertextBlob;
}

export const numberify = (a: any): number | undefined => {
  // check if defined & is not NaN
  if (a && !isNaN(+a)) {
    return Number(a);
  }
};

export async function checkPayload(checkType: PayloadType.ROLE | PayloadType.OTHER, payload: any, type: any): Promise<void>;
export async function checkPayload(checkType: PayloadType.AWS_ACCESSKEY | PayloadType.AWS_SECRETKEY, payload: string | undefined): Promise<void>;

export async function checkPayload(checkType: PayloadType, payload: any, type?: any): Promise<void> {
  switch (checkType) {
    case PayloadType.UUID:
      if (!/^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i.test(payload)) { throw new CusError(400, 'Bad Request', `Invalid Client UUID: ${payload}`); }
      break;
    case PayloadType.EMAIL:
      // eslint-disable-next-line no-useless-escape
      if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(payload)) { throw new CusError(400, 'Bad Request', `Invalid Email: ${payload}`); }
      break;
    case PayloadType.AWS_ACCESSKEY:
      if (!/^(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])$/i.test(payload)) { throw new CusError(400, 'Bad Request', `Invalid AWS Access Key: ${payload}`); }
      break;
    case PayloadType.AWS_SECRETKEY:
      if (!/^(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])$/i.test(payload)) { throw new CusError(400, 'Bad Request', `Invalid AWS Secret Key: ${payload}`); }
      break;
    case PayloadType.ROLE:
      if (!Object.values(type).includes(payload)) { throw new CusError(400, 'Bad Request', `Invalid Role: ${payload}`); }
      break;
    case PayloadType.OTHER:
      if (!Object.values(type).includes(payload)) { throw new CusError(400, 'Bad Request', `Invalid ${type}: ${payload}`); }
      break;
    default:
      throw new CusError(400, 'Bad Request', 'Invalid Parameter Value');
  }
}

export function paginate(array: any[], limit: number, page: number) {
  return array.slice((page - 1) * limit, page * limit);
}

export function addMonths(date: Date, months: number): Date {
  const d = date.getDate();
  const dateObj = new Date(date.getTime());
  dateObj.setMonth(dateObj.getMonth() + +months);
  if (dateObj.getDate() !== d) {
    dateObj.setDate(0);
  }
  return dateObj;
}

export async function checkSamlCredential(id: string): Promise<{ id: string }> {
  const samlAssertion = await getSamlResponse(id, 'stsApi');
  const params = {
    DurationSeconds: 900,
    PrincipalArn: `arn:aws:iam::${id}:saml-provider/Demo-IdP`,
    RoleArn: `arn:aws:iam::${id}:role/DemoSAMLRole`,
    SAMLAssertion: samlAssertion,
  };
  // first assume role with SAML
  const credentials = (await new AWS.STS().assumeRoleWithSAML(params).promise()).Credentials;
  if(credentials) {
    const sts = new AWS.STS({
      credentials: {
        accessKeyId: credentials?.AccessKeyId,
        secretAccessKey: credentials?.SecretAccessKey,
        sessionToken: credentials?.SessionToken,
      }
    });
    const callerId = (await sts.getCallerIdentity().promise()).Account;
    if (id != callerId) throw new CusError(400, 'Validate Failed', 'Invalid Credential');
    return { id };
  } else {
    throw new CusError(400, "CredentialNotFoundException", "The credential not found.")
  }
  // next validate the assumed role with STS is the right account
}
