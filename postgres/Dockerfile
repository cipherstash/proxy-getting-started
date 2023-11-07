FROM postgres:12.1
COPY demo.sql /demo.sql

EXPOSE 5432

COPY init.sh /docker-entrypoint-initdb.d/init.sh

CMD [ "-p", "5432" ]