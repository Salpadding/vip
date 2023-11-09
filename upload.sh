for ho in 192.168.1.39; do
    echo 'mkdir -p ${HOME}/vip' | ssh ubuntu@${ho} 'bash'
    rsync -azvp ./vip ubuntu@${ho}:vip/vip
    rsync -azvp ./Caddyfile ubuntu@${ho}:vip/Caddyfile
    rsync -azvp ./ingress-http.service ubuntu@${ho}:vip/ingress-http.service
    rsync -azvp ./config.json ubuntu@${ho}:vip/config.json
    echo 'sudo cp vip/ingress-http.service /etc/systemd/system' | ssh ubuntu@${ho} bash
    echo 'sudo systemctl daemon-reload && sudo systemctl enable ingress-http && sudo systemctl restart ingress-http' | ssh ubuntu@${ho} bash
done
