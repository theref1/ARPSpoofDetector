#pragma once
#include <string>


/*
* represent line of arp table 
*/
struct TableArpLine
{
	std::string ipAdress;    //ip address of device
	std::string macAdress;   //mac address of device
};


/*
* @ifaceIp is the ip address of the interface you want to scan
*/
bool detectArpSpoof(std::string ifaceIp);   // fonctio who detect a arp poisoning 
