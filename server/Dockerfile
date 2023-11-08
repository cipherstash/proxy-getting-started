FROM node

WORKDIR /app
COPY package.json .
COPY package-lock.json .
RUN npm i

COPY server.js /app/
EXPOSE 3001

CMD ["npm", "start"]