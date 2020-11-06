# -*- coding: utf-8 -*-
import os, json, nmap, re
from Log import *
from createXLS import *
from IPy import IP
import traceback

class PublicScan:
    def __init__(self, rate='2000'):
        self.rate = rate
        self.result_info, self.change_del_list, self.change_add_list, self.measscan_result = [], [], [], []
        self.ip_list = []

    def readResult(self):
        if os.path.exists('tmp/tempResult'):
            with open('tmp/tempResult') as f:
                contents = f.read().split('\n')
            for line in contents:
                if not line:
                    continue
                ip, port = line.split(':')
                self.measscan_result.append([ip, int(port)])
            print self.measscan_result            
            return True
        else:
            return False

    def Public_nmap(self, ipinfo=None):
        for ip_port in self.measscan_result:
            scanner = nmap.PortScanner()
            port = ip_port[1] if isinstance(ip_port[1], int) else int(ip_port[1])
            scanner.scan(hosts=ip_port[0], arguments='-sS -T4 -p %d' % port)
            for targethost in scanner.all_hosts():
                for proto in scanner[targethost].all_protocols():
                    lport = scanner[targethost][proto].keys()
                    lport.sort()
                    for port in lport:
                        if scanner[targethost][proto][port]['state'] == 'open':
                            temp = {}
                            temp['ip'] = targethost
                            temp['port'] = port
                            temp['server'] = scanner[targethost][proto][port]['name']
                            temp['state'] = 'open'
                            temp['protocol'] = proto
                            temp['product'] = scanner[targethost][proto][port]['product']
                            temp['product_version'] = scanner[targethost][proto][port]['version']
                            temp['product_extrainfo'] = scanner[targethost][proto][port]['extrainfo']
                            temp['reason'] = scanner[targethost][proto][port]['reason']
                            self.result_info.append("%s:%s:%s" % (temp['ip'], temp['port'], temp['server']))

    def diff(self):
        if os.path.exists('out/Result.txt'):
            oldlist = []
            with open('out/Result.txt') as f:
                for line in f:
                    oldlist.append(line.strip())
            old_change_list = list(set(oldlist).difference(set(self.result_info)))
            if old_change_list:
                self.Public_nmap(old_change_list)
                self.change_del_list = list(set(oldlist).difference(set(self.result_info)))
            self.change_add_list = list(set(self.result_info).difference(set(oldlist)))

    def callback(self):
        if not os.path.exists('out'):
            os.mkdir('out')
        fl = open('out/Result.txt', 'w')
        for i in self.result_info:
            fl.write(i)
            fl.write("\n")
        fl.close()

    def checkip(self, ip):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            return True
        else:
            return False


    def run(self):
        logger = LogInfo('log/process.log')

        logger.infostring('Start myscan...')
        logger.infostring('start read results...')
        if not self.readResult():
            logger.infostring('masscan scanning problems, IP files may be wrong.')
            logger.infostring('program exits')
            return [], [], ""
        print(len(self.measscan_result))
        logger.infostring('start nmap scan service...')
        self.Public_nmap()
        logger.infostring('finsh nmap scan.')

        logger.infostring('compare with the last result')
        self.diff()

        logger.infostring('generate the result file')
        self.callback()
        return self.result_info, self.change_add_list, self.change_del_list


if __name__ == '__main__':
    conf_info = {}
    conf_info['result_info'], conf_info['change_add_list'], conf_info['change_del_list'], conf_info['weakpass_result'], \
    conf_info['xlsfile'], = \
        [], [], [], [], ""
    try:
        nmap_scan = PublicScan()
        conf_info['result_info'], conf_info['change_add_list'], conf_info['change_del_list'] = nmap_scan.run()
        Create_Xls(conf_info).run()
    except:
        traceback.print_exc()
