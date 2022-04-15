MITM_NAME=mitm_attack
MITM_FILE_NAME=mitm_attack.py

PHAM_NAME=pharm_attack
PHAM_FILE_NAME=pharm_attack.py

all: $(MITM_NAME) $(PHAM_NAME)
	echo "Build finished!"

$(MITM_NAME): $(MITM_FILE_NAME)
	cp $(MITM_FILE_NAME) $(MITM_NAME)
	chmod +x $(MITM_NAME)
	mkdir -p sslsplit-log
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8888
	openssl req -x509 -new -nodes -sha256 -utf8 -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt -config ssl.conf

$(PHAM_NAME): $(PHAM_FILE_NAME)
	cp $(PHAM_FILE_NAME) $(PHAM_NAME)
	chmod +x $(PHAM_NAME)

clean:
	sudo rm -f $(PHAM_NAME) $(MITM_NAME) *.o server.key server.crt
	sudo rm -rf sslsplit-log

zip:
	zip 0816153.zip Makefile $(MITM_FILE_NAME) $(PHAM_FILE_NAME) report.pdf ssl.conf && \
	echo "\nZip file successfully build!"