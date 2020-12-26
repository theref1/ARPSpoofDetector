#include <iostream>
#include "TableArpLine.h"


int main()
{
	std::string iface;
	std::cout << "Entrez l'addresse ip de l'interface ? ";
	std::cin >> iface;
	detectArpSpoof(iface);
	return 0;
}