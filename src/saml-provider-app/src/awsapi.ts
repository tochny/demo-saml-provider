import AWS from 'aws-sdk';

const {
  AWS_DEFAULT_REGION,
} = process.env;

export const paramStore = new AWS.SSM({
  region: AWS_DEFAULT_REGION,
});

export const secretsManager = new AWS.SecretsManager({
  region: AWS_DEFAULT_REGION,
  apiVersion: '2017-10-17',
});

export const dynamoDB = new AWS.DynamoDB.DocumentClient({
  apiVersion: '2012-08-10',
  region: AWS_DEFAULT_REGION,
});

export const kms = new AWS.KMS({
  region: AWS_DEFAULT_REGION,
});

export const cISP = new AWS.CognitoIdentityServiceProvider({
  apiVersion: '2016-04-18',
  region: AWS_DEFAULT_REGION,
});

export const s3 = new AWS.S3({
  apiVersion: '2006-03-01',
});

export const ses = new AWS.SES({
  region: AWS_DEFAULT_REGION,
});

export const ecs = new AWS.ECS({
  region: AWS_DEFAULT_REGION,
});

export const cloudFront = AWS.CloudFront;
