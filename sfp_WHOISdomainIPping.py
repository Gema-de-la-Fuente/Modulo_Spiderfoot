# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_WHOISdomainIPping
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Gema de la Fuente Romero <gem.fuente@gmail.com>
#
# Created:     08/12/2021
# Copyright:   (c) Gema de la Fuente Romero 2021
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import whois
from ipwhois import IPWhois
from IPy import IP
import os

class sfp_WHOISdomainIPping(SpiderFootPlugin):

    meta = {
        'name': "sfp_WHOISdomainIPping",
        'summary': "Hace un whois a dominios e ips introducidos y envia un ping para informar si esta levantado el servicio>",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options No hacemos fuerza bruta
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            #datos = ['google.com', 'donnierock.com','140.82.114.4', '127.0.0.1']
            datos = 'donnierock.com'
            
            def hacerPing(dato):
                estado = os.system('ping -c 1 '+ dato)
                print('Hace PING en '+ dato) if estado == 0 else print('No hace PING en '+ dato)

            for dato in datos:
                print(dato)
                #miramos si es una ip
                try:
                    if IP(dato):
                        #miramos si es una ip publica
                        if IP(dato).iptype() == 'PUBLIC':
                            datoIp = IPWhois(dato)
                            print(datoIp.lookup_whois())
                            hacerPing(dato)
                            print('-----------------------------')
                        else:
                            print('La Ip introducida '+ dato + ' no es PUBLICA')
                            print('-----------------------------')
                    
                except:
                    print(whois.whois(dato))
                    hacerPing(dato)
                    print('-----------------------------')
            #############################
            if not data:
                self.sf.error("Unable to perform stp_whois on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the stp_whois on " + eventData + ": " + str(e))
            return


        evt = SpiderFootEvent("DOMAIN_NAME", datos, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_WHOISdomainIPping class
