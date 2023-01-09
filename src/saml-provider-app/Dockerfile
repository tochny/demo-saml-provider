FROM node:16 as base-env

WORKDIR /app
COPY ./src/layer-application/nodejs .

RUN yarn --production

FROM node:16 as build-env

WORKDIR /app

COPY ./src/saml-provider-app .
COPY ./src/layer-application/nodejs .

RUN yarn && yarn run build

FROM node:16
WORKDIR /app
COPY --from=base-env /app/node_modules ./node_modules
COPY --from=build-env /app/dist .
ENV DOCKER=true
EXPOSE 3000
ENTRYPOINT [ "yarn", "start" ]
