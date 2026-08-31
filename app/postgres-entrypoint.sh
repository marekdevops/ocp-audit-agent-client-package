#!/bin/sh
set -eu

export PGDATA="${PGDATA:-/var/lib/postgresql/data}"
export POSTGRES_USER="${POSTGRES_USER:-ocp_audit}"
export POSTGRES_DB="${POSTGRES_DB:-ocp_audit}"
export PATH="$(pg_config --bindir):${PATH}"
if ! getent passwd "$(id -u)" >/dev/null 2>&1; then
  export NSS_WRAPPER_PASSWD=/tmp/passwd.nss_wrapper
  export NSS_WRAPPER_GROUP=/tmp/group.nss_wrapper
  printf 'audit:x:%s:%s::/app:/sbin/nologin\n' "$(id -u)" "$(id -g)" > "${NSS_WRAPPER_PASSWD}"
  printf 'audit:x:%s:\n' "$(id -g)" > "${NSS_WRAPPER_GROUP}"
  export LD_PRELOAD=libnss_wrapper.so
fi
mkdir -p "${PGDATA}"
if [ ! -f "${PGDATA}/PG_VERSION" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"
  initdb -D "${PGDATA}" --username="${POSTGRES_USER}" --auth-host=scram-sha-256 --auth-local=trust
  pg_ctl -D "${PGDATA}" -o "-c listen_addresses='' -c unix_socket_directories=/tmp" -w start
  psql --host=/tmp --username="${POSTGRES_USER}" --dbname=postgres -c "ALTER USER \"${POSTGRES_USER}\" PASSWORD '${POSTGRES_PASSWORD}';"
  createdb --host=/tmp --username="${POSTGRES_USER}" "${POSTGRES_DB}"
  pg_ctl -D "${PGDATA}" -m fast -w stop
fi

# initdb only permits TCP clients from localhost. Application pods connect
# through the PostgreSQL Service, so allow routed pod addresses while still
# requiring SCRAM authentication for every TCP connection.
for rule in \
  "host all all 0.0.0.0/0 scram-sha-256" \
  "host all all ::/0 scram-sha-256"
do
  if ! grep -Fqx "${rule}" "${PGDATA}/pg_hba.conf"; then
    printf '%s\n' "${rule}" >> "${PGDATA}/pg_hba.conf"
  fi
done

# OpenShift SCC-assigned fsGroup handling can make a mounted data directory
# group-writable on each pod start. PostgreSQL refuses PGDATA in that mode.
chmod 0700 "${PGDATA}"

exec postgres -D "${PGDATA}" -c listen_addresses='*' -c unix_socket_directories=/tmp
