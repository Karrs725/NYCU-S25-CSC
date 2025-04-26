CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDLIBS = -lpthread -lnetfilter_queue

all: icmp_redirect pharm_attack

icmp_redirect: icmp_redirect.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

pharm_attack: pharm_attack.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f icmp_redirect pharm_attack