import { randomUUID } from 'crypto';
import { Buffer } from 'node:buffer';
import saml from 'saml';

import { parameterPath } from './app';
import { getParameterStoreValue, getSecretValue, logger } from './common';

async function getCertAndKey() {
  const { privateKey, cert } = await getSecretValue('/samlp/SAMLSign');
  // a bug in Buffer.from that cannot decode carriage return to the correct format [0xA]
  return {
    cert: Buffer.from(JSON.parse((`"${cert.replace('"', '\\"')}"`))),
    key: Buffer.from(JSON.parse((`"${privateKey.replace('"', '\\"')}"`))),
  };
}

// generate a ID for the SAML response length 20
function generateUniqueID(): string {
  return randomUUID().replace(/-/g, '').substring(0, 20);
}

function removeHeaders(cert: any): string | null {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

async function buildSamlResponse(id: string, nameId: string): Promise<string> {
  const issuer = await getParameterStoreValue(`${parameterPath}/FrontendBaseUrl`);
  const { cert, key } = await getCertAndKey();
  const samlOptions = {
    issuer,
    cert,
    key,
    audiences: 'https://signin.aws.amazon.com/saml',
    recipient: 'https://signin.aws.amazon.com/saml',
    lifetimeInSeconds: 3600,
    attributes: {
      'https://aws.amazon.com/SAML/Attributes/Role': `arn:aws:iam::${id}:role/DemoSAMLRole,arn:aws:iam::${id}:saml-provider/Demo-IdP`,
      'https://aws.amazon.com/SAML/Attributes/RoleSessionName': nameId,
    },
    nameIdentifier: nameId,
    nameIdentifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    sessionIndex: `_${randomUUID()}`,
  };
  // get saml signed assertion
  const samlAssertion = saml.Saml20.create(samlOptions);
  const SAMLResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${generateUniqueID()}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${samlOptions.audiences}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${samlOptions.issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="'urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${samlAssertion}</samlp:Response>`;
  logger.info('SAMLResponse', SAMLResponse)
  const cannonicalized = SAMLResponse
    .replace(/\r\n/g, '')
    .replace(/\n/g, '')
    .replace(/>(\s*)</g, '><') //unindent
    .trim();
  const sig = new SignedXml(null, {
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  });

  sig.addReference("//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    "http://www.w3.org/2001/04/xmlenc#sha256");
  sig.signingKey = key;
  const pem = removeHeaders(cert);
  sig.keyInfoProvider = {
    file: '',
    getKeyInfo: function (key, prefix) {
      prefix = prefix ? prefix + ':' : prefix;
      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + pem + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
    },
    getKey: function (keyInfo) {
      return key;
    }
  };

  sig.computeSignature(cannonicalized, {
    location: {
      reference: "//*[local-name(.)='Issuer']",
      action: 'after'
    }
  });
  logger.info(sig.getSignedXml());
  return sig.getSignedXml();
  return SAMLResponse;
}

async function buildSamlMetadata(): Promise<string> {
  const _claimtypes = [
    '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="E-Mail Address" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>',
    '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="Given Name" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>',
    '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="Name" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>',
    '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="Surname" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>',
    '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="Name ID" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>',
  ];
  const issuer = await getParameterStoreValue(`${parameterPath}/FrontendBaseUrl`);
  const { cert } = await getCertAndKey();
  const pem = removeHeaders(cert);
  const metadata = `<EntityDescriptor entityID="${issuer}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${pem}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${issuer}/auth/samlp/logout"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${issuer}/auth/samlp/logout"/><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat><NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${issuer}/auth/samlp/login"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${issuer}/auth/samlp/login"/>${_claimtypes.join('')}</IDPSSODescriptor></EntityDescriptor>`;
  return metadata;
}

export async function getSamlResponse(id: string, nameId: string): Promise<string> {
  logger.info(`${nameId} is calling getSamlResponse on ${id}`);
  return Buffer.from(await buildSamlResponse(id, nameId)).toString('base64');
}

export async function getSamlMetadata(): Promise<string> {
  return buildSamlMetadata();
}
