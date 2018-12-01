#!/usr/bin/env python

import argparse
import terminal_banner
from scapy.all import *
from scapy.error import Scapy_Exception
from pyfiglet import Figlet
from scapy.layers.inet import TCP


def Banner ():
    banner = Figlet(font='slant')
    print (banner.renderText('Baiacu Sniffer'))

Banner()
b_text = "Bem vindo ao BAIACU SNIFFER \nCode By : Caio Kuruta\n=====================================X=====================================\nUse -h para ajuda\nUse --man para o manual completo da ferramenta"

m_banner = terminal_banner.Banner(b_text)
print (m_banner)



type_sf = ""  # Parametro que sera inserido no ``filter``


parse = argparse.ArgumentParser(description="")


parse.add_argument("-man","--man",help="Exibe o manual ",action="store_true")
parse.add_argument("-hx","--hex",help="Mostra o pacote em hexadecimal" ",action="store_true")
parse.add_argument("-a","--arp",help="Define o snnifing arp",action="store_true")
parse.add_argument("-t","--tcp",help="Define o snnifing tcp",action="store_true")
parse.add_argument("-u","--udp",help="Define o snnifing udp",action="store_true")
parse.add_argument("-I","--ip",help="Define o snnifing ip",action="store_true")
parse.add_argument("-i","--icmp",help="Define o snnifing icmp",action="store_true")
parse.add_argument("-sO","--saveo",help="Salva o Sniffing em um arquivo .pcap ",action="store")
parse.add_argument("-s","--sum",help="A saida exibe uma lista de resumos de cada pacote",action="store_true")
parse.add_argument("-S","--show",help="A saida exibe o sinnifing de forma mais completa",action="store_true")
parse.add_argument("-sP","--passw",help="Tenta o snnifing de logins e senhas *NO HTTPS*",action="store_true")
parse.add_argument("-H","--host",help="Filtra pacotes do endereco IP designado",action="store",type=str)
parse.add_argument("-p","--port",help="Filtra a porta que deseja sniffar",action="store",type=int)

args = parse.parse_args()

if args.man:
    
    arquivo = open("Manual.txt","r")
    for linha in arquivo:
        print (linha)



# Cadeia de estrutura que permite moldar a variavel `type_sf` para inseri-la no filter do sniffer#

#=================================================================================================#
if args.tcp:                                                                                      #
    if re.search('arp' or 'icmp' or 'udp'or 'ip',type_sf):                                        #
        type_sf = type_sf + 'and tcp'                                                             #
    else:                                                                                         #
        type_sf = 'tcp'                                                                           #
#=================================================================================================#
if args.udp:                                                                                      #
    if re.search('tcp' or 'ip'or 'arp' or 'icmp',type_sf):                                        #
        type_sf = type_sf + ' and udp'                                                            #
    else:                                                                                         #
        type_sf = 'udp'                                                                           #
#=================================================================================================#
if args.icmp:                                                                                     #
    if re.search('tcp' or 'udp' or 'arp' or 'ip', type_sf):                                       #
        type_sf = type_sf + ' and icmp'                                                           #
    else:                                                                                         #
      type_sf ='icmp'                                                                             #
#=================================================================================================#
if args.ip:                                                                                       #
    if re.search('tcp' or 'udp' or 'icmp' or 'arp', type_sf):                                     #
        type_sf = type_sf + " and ip"                                                             #
    else:                                                                                         #
        type_sf = "ip"                                                                            #
#=================================================================================================#
if args.arp:                                                                                      #
    if re.search('tcp' or 'udp' or 'icmp' or 'ip', type_sf):                                      #
        type_sf = type_sf + ' and arp'                                                            #
    else:                                                                                         #
        type_sf = ' arp'                                                                          #
#=================================================================================================#
if args.port:                                                                                     #
    if re.search('tcp' or 'udp' or 'icmp' or 'ip' or 'arp' or 'host', type_sf):                   #
        type_sf = type_sf + ' and port '+ str(args.port)                                          #
    else:                                                                                         #
        type_sf = 'port ' + str(args.port)                                                        #
#=================================================================================================#
if args.host:                                                                                     #
    if re.search('tcp' or 'udp' or 'icmp' or 'ip' or 'arp' or 'port', type_sf):                   #
        type_sf = type_sf + ' and host '+ str(args.host)                                          #
    else:                                                                                         #
        type_sf = 'host ' + str(args.host)                                                        #
#=================================================================================================#


print (type_sf)



            # Funcao que permite mostrar os pacotes logo que sao capturados #


def print_pack(pack):
###################################################Mostrar pacote com resumo############################################
    if args.sum:
        try:
            print(pack.summary())
            print('-------------------------------------------------------------------------')
        except Scapy_Exception as erro:
            print('Erro encontrado -------------------------> ',erro)
###############################################Mostrar pacote com detalhes##############################################
    elif args.show:
        try:
            print(pack.show())

        except Scapy_Exception as erro :
            print('Erro encontrado -----------------------------> ',erro)
######################################################SEM ARGUMENTOS#################################################
    elif args.sem:
        try:
            print(pack)
        except Scapy_Exception as erro:
            print('Erro encontrado --------------------------> ',erro)
###########################################SCAPTURA DE SENHAS E LOGINS##################################################
    elif args.passw:
        try:
            header = str (pack[TCP].payload)[0:4]
            if header.lower() == 'post':
                if 'pass' or 'senha' or 'login' in str([TCP].payload).lower():
                    print(pack.show())
        except Scapy_Exception as erro:
            print ('Erro -----------------------------> ' ,erro)
##########################################################################################################
    elif args.hex:
        try:                
            print(hexdump(pack))       
        except Scapy_Exception as erro:
            print ('Erro -----------------------------> ' ,erro)
###############################SALVAR EM ARQUIVO########################################################################
                   
                   
    if args.saveo:
        n = str(args.saveo)
        wrpcap(n,pack,append=True)
#######################################################################################################################



sniff(filter=type_sf, prn=print_pack)
