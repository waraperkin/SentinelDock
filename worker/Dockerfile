FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
COPY worker/package.json ./worker/package.json
RUN npm install --workspace=worker --include-workspace-root
COPY worker ./worker
RUN npm run build -w worker

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
RUN apk add --no-cache iproute2
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/worker/dist ./worker/dist
COPY --from=build /app/worker/package.json ./worker/package.json
CMD ["node", "worker/dist/index.js"]
