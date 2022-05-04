APP_SEV=attacker_server
APP_SEV_FILE=attacker_server.py

APP_CRK=crack_attack
APP_CRK_FILE=crack_attack.py

all: $(APP_SEV) $(APP_CRK)
	echo "Build finished!"


$(APP_SEV): $(APP_SEV_FILE)
	cp $(APP_SEV_FILE) $(APP_SEV)
	chmod +x $(APP_SEV)

$(APP_CRK): $(APP_CRK_FILE)
	cp $(APP_CRK_FILE) $(APP_CRK)
	chmod +x $(APP_CRK)

clean:
	rm -f $(APP_SEV) $(APP_CRK)

zip:
	zip 0816153.zip Makefile $(APP_CRK_FILE) $(APP_SEV_FILE) && \
	echo "\nZip file successfully build!"
