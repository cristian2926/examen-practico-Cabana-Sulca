#!/bin/bash
# simular_bruteforce.sh
# Simula un ataque de fuerza bruta SSH inyectando entradas en syslog
# via el comando 'logger', que Wazuh monitorea en /var/log/auth.log.
# Activa la regla nativa 5716 (Failed password) y luego la regla
# personalizada 100001 al superar 10 intentos desde la misma IP en 60s.
#
# Uso:
#   sudo bash simular_bruteforce.sh [IP_ATACANTE] [INTENTOS]
#   sudo bash simular_bruteforce.sh 45.33.32.156 15

ATTACKER_IP="${1:-45.33.32.156}"
COUNT="${2:-15}"
TARGET_USERS=("root" "admin" "ubuntu" "deploy" "postgres" "test")

echo "=============================================="
echo " Simulador de Fuerza Bruta SSH — Lab 2 Wazuh"
echo "=============================================="
echo " IP atacante : $ATTACKER_IP"
echo " Intentos    : $COUNT (umbral regla: 10 en 60s)"
echo "----------------------------------------------"

for i in $(seq 1 "$COUNT"); do
    USER=${TARGET_USERS[$((RANDOM % ${#TARGET_USERS[@]}))]}
    PORT=$((RANDOM % 64511 + 1024))
    logger -p auth.warning -t sshd \
        "Failed password for ${USER} from ${ATTACKER_IP} port ${PORT} ssh2"
    echo "  [+] Intento $i/$COUNT — usuario: ${USER}  puerto: ${PORT}"
    sleep 0.4
done

echo "----------------------------------------------"
echo "[+] Simulacion completada."
echo "[*] Verificar alertas:"
echo "    sudo tail -50 /var/ossec/logs/alerts/alerts.log | grep -A8 '100001'"
