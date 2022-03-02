

CXX=g++

APP_NAME=dns_attack
FILE_NAME=main.cpp

$(APP_NAME): $(FILE_NAME)
	$(CXX) -o $(APP_NAME) $(FILE_NAME)

test: test.cpp
	$(CXX) -o test.o test.cpp

clean:
	rm -f $(APP_NAME) *.o