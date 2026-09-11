FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
COPY frontend/package.json ./frontend/package.json
RUN npm install --workspace=frontend --include-workspace-root
COPY frontend ./frontend
ARG NEXT_PUBLIC_API_URL=http://localhost:4000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build -w frontend

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/frontend/.next ./frontend/.next
COPY --from=build /app/frontend/public ./frontend/public
COPY --from=build /app/frontend/package.json ./frontend/package.json
COPY --from=build /app/frontend/next.config.mjs ./frontend/next.config.mjs
WORKDIR /app/frontend
EXPOSE 3000
CMD ["npm", "run", "start"]
