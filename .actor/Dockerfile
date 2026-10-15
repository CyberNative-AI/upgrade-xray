FROM apify/actor-node:24

# Python is used only to parse Python sources with the standard-library ast module.
USER root
RUN (command -v apk >/dev/null && apk add --no-cache python3) || (apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*)
# The base image pre-installs apify, crawlee and typescript in a root-owned node_modules that npm,
# running as myuser, cannot replace. Every dependency comes from package-lock.json instead.
RUN rm -rf /usr/src/app/node_modules
USER myuser

COPY --chown=myuser package*.json ./
RUN npm --quiet set progress=false \
    && npm ci --omit=dev --omit=optional --ignore-scripts \
    && echo "Installed NPM packages:" \
    && (npm list --omit=dev --all || true) \
    && node --version && python3 --version

COPY --chown=myuser . ./

CMD npm start --silent
