#include "TableArpLine.h"
#include <stdlib.h>
#include<vector>
#include<fstream>
#include<iostream>
#include<string>

bool detectArpSpoof(std::string ifaceIp)
{
    std::string defaultGatewayIp;           //ip address of default gateway
    std::string defaultGatewayMac;          //mac address of default gateway

    std::vector<TableArpLine*> arpTable;   // all lines of arp table

    std::string meaningLessWord;       //string who help us to skip a meaningless word

    std::string commandArp = "arp -a -N " + ifaceIp + " > arpResult.txt";

    system((char*)commandArp.c_str());      

    std::ifstream arpResult("arpResult.txt");
    arpResult.seekg(50, std::ios::beg);
    
    while (std::getline(arpResult, commandArp))
    {
        TableArpLine* lines = new TableArpLine;
        arpResult >> lines->ipAdress;
        arpResult >> lines->macAdress;
        arpResult >> meaningLessWord;
        arpTable.push_back(lines);
    }

    system("ipconfig > ipconfigResult.txt");        //EXEC IPCONFIG COMMAND TO GET A DEFAULT GATEWAY
    std::ifstream ipconfigResult("ipconfigResult.txt");

    while (ipconfigResult && !ipconfigResult.eof())
    {
        std::getline(ipconfigResult, meaningLessWord);

        if (meaningLessWord.find(ifaceIp) != std::string::npos)
        {
            std::getline(ipconfigResult, defaultGatewayIp);
         
            /*read 12 words to get the default gateway ip*/
            for (int i = 0; i < 12; i++)
            {
                ipconfigResult >> defaultGatewayIp;
            }
        }     
    }
 
    arpResult.close();
    ipconfigResult.close();


    for (size_t i = 0; i < arpTable.size(); i++)
    {
        if (arpTable[i]->ipAdress == defaultGatewayIp)
            defaultGatewayMac = arpTable[i]->macAdress;

    }

    for (size_t i = 0; i < arpTable.size(); i++)
    {
        if (arpTable[i]->ipAdress != defaultGatewayIp && arpTable[i]->macAdress == defaultGatewayMac)
        {
            std::cout << "Vous etes victime d'une attaque MITM" << std::endl;
            return true;
        }
           

    }
    std::cout << "Vous n'etes pas victime d'une attaque MITM" << std::endl;
    return false;
}
