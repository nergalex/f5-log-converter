echo "Start Unit" > /var/log/docker-entrypoint.log
#unitd --control 0.0.0.0:8000
#echo "Configure Unit certificate" >> /var/log/docker-entrypoint.log
#export FAAS_APP_NAME=logstream-xc
#curl -X PUT --data-binary @/docker-entrypoint.d/${FAAS_APP_NAME}.pem http://localhost:8000/certificates/${FAAS_APP_NAME}
#echo "Configure Unit App" >> /var/log/docker-entrypoint.log
#curl -X PUT --data-binary @/docker-entrypoint.d/${FAAS_APP_NAME}.json http://localhost:8000/config/
#echo "Stop Unit" >> /var/log/docker-entrypoint.log
#pkill -f unit
#pkill --signal SIGKILL unit
#echo "Start Unit as non-daemon" >> /var/log/docker-entrypoint.log
#unitd --no-daemon --control 0.0.0.0:8000
#echo "End" >> /var/log/docker-entrypoint.log





