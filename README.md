# Demo SAML Identity Provider
This is a simple demonstration of a SAML identity provider (IDP) using the SAML2int gem and TypeScript.

## Prerequisites
Node.js 16 or higher
TypeScript
Yarn

## Installation
Clone this repository
Run `yarn` to install dependencies
Compile the TypeScript code with `yarn build`
Start the server with `yarn start`
The IDP will be available at http://localhost:3000

## Usage
Configure service provider (SP) to point to the IDP's metadata URL: http://localhost:3000/samlp/FederationMetadata/2007-06/FederationMetadata.xml

## Configuration
The IDP can be configured using the following environment variables:

LOGIN_URL: The URL of the IDP's login endpoint (default: http://localhost:3000/auth/samlp/login)
authToken: The pregenerated auth token to use for signing the SAML response
nameId: The name identifier to use for the SAML response
platformId: The user/platform ID to use for the SAML response

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details
