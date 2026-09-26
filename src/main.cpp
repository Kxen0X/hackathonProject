#include "server.h"
int main() {


	Server server(3000);
	server.Start();
	server.wait();
	

	return 0;
}