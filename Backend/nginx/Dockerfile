FROM nginx:1.19.0-alpine

COPY ./cert.crt /etc/ssl
COPY ./key.key /etc/ssl
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

