echo "Start Unit" > /unit/docker-entrypoint.log
unitd --control 0.0.0.0:8000 --pid /unit/unit.pid --state /unit/ --tmp /unit/ --log /unit/unit.log
echo "Configure Unit certificate" >> /unit/docker-entrypoint.log
export FAAS_APP_NAME=logstream-xc
curl -X PUT --data-binary @/docker-entrypoint.d/${FAAS_APP_NAME}.pem http://localhost:8000/certificates/${FAAS_APP_NAME}
echo "Configure Unit App" >> /unit/docker-entrypoint.log
curl -X PUT --data-binary @/docker-entrypoint.d/${FAAS_APP_NAME}.json http://localhost:8000/config/
echo "Stop Unit" >> /unit/docker-entrypoint.log
pkill -f unit
pkill --signal SIGKILL unit
echo "Start Unit as non-daemon" >> /unit/docker-entrypoint.log
unitd --no-daemon --control 0.0.0.0:8000 --pid /unit/unit.pid --state /unit/ --tmp /unit/ --log /unit/unit.log
echo "End" >> /unit/docker-entrypoint.log





