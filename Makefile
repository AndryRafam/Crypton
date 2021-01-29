SRC:= $(wildcard Function/AES.cpp) \
	  $(wildcard Function/IMPALA.cpp) \
	  $(wildcard Main/Main.cpp)


LDFLAGS:= -lcryptopp

OBJECTS:= $(SRC:.cpp=.o)

impala: $(OBJECTS)
	 	$(CXX) -o $@ $^ $(LDFLAGS)
