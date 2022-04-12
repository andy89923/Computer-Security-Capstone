CXX=g++ -lpthread

MITM_NAME=mitm_attack
MITM_FILE_NAME=mitm_attack.cpp

PHAM_NAME=pharm_attack
PHAM_FILE_NAME=pharm_attack.cpp

# $(APP_NAME): $(FILE_NAME)
# 	$(CXX) -o $(APP_NAME) $(FILE_NAME)

all: $(MITM_NAME) $(PHAM_NAME)
	echo "Build finished!"

$(MITM_NAME): $(MITM_FILE_NAME)
	$(CXX) -o $(MITM_NAME) $(MITM_FILE_NAME)

$(PHAM_NAME): $(PHAM_FILE_NAME)
	$(CXX) -o $(PHAM_NAME) $(PHAM_FILE_NAME)

clean:
	sudo systemd-resolve --flush-caches
	rm -f $(PHAM_NAME) $(MITM_NAME) *.o
