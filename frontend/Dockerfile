# The web interface: built with Node, served by nginx, which also passes
# /api/ on to the API. Built from this folder: docker build -t log-analyzer-web frontend
FROM node:22-alpine AS build

WORKDIR /src

# Dependencies first: this layer is rebuilt only when the lock file changes.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
# Where the pages look for the API. A path, so the same origin the page came from.
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build


FROM nginx:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD ["wget", "--quiet", "--spider", "http://127.0.0.1/"]
