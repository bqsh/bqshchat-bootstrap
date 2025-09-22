#!/bin/sh
set -e

tor &

sleep 1

if [ -f /var/lib/tor/hidden_service/hostname ]; then
  echo "== ONION HOSTNAME =="
  cat /var/lib/tor/hidden_service/hostname
  echo "===================="
fi

# Запускаем приложение
echo "Запуск приложения..."
/app/p2p-forum