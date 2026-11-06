FROM node:latest
WORKDIR /app
RUN curl -fsSL https://example.com/install.sh | sh
COPY . .
RUN npm install
EXPOSE 3000
CMD ["node", "index.js"]
