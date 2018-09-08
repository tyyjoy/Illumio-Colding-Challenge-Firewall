import csv
import ipaddress

class Firewall(object):
    rules = {}
    
    def __init__(self, file):
        with open(file, 'r') as data:
            for line in data:
                valid_idx = line.find("\n")
                line = line[:valid_idx]
                direction, protocol, port, ip = line.split(',')
                if '-' in port:
                    min_P, max_P = port.split('-')
                    # use the generator to save runtime space
                    for p in self.generate_port(int(min_P), int(max_P)+1):
                        key = direction + protocol + str(p)
                        if key not in self.rules:
                            self.ini_dicts(key)
                        self.add_ipadress(key, ip)
                else:
                    key = direction + protocol + port
                    if key not in self.rules:
                        self.ini_dicts(key)
                    self.add_ipadress(key, ip)            

    def generate_port(self, min_port, max_port):
        for port in range(min_port, max_port):
            yield port
            
    def ini_dicts(self, key):
        self.rules[key] = {}
        self.rules[key]['single'] = set()
        self.rules[key]['range'] = [] 
    
    def add_ipadress(self, key, ip):
        if '-' in ip:
            self.rules[key]['range'].append(ip)
        else:
            self.rules[key]['single'].add(ip)
    
    def accept_packet(self, direction, protocol, port, ip_address):
        
        if self.validation_check(direction, protocol, port, ip_address) is False:
            return False
        key = direction + protocol + str(port)
        if key in self.rules:
            return self.check_ipaddress(key, ip_address)
        else:
            return False
    
    def check_ipaddress(self, key, ip_address):
        if ip_address in self.rules[key]['single']:
            return True
        for _ in self.rules[key]['range']:
            min_ip, max_ip = _.split('-')
            min_ip = int(ipaddress.IPv4Address(min_ip))
            max_ip = int(ipaddress.IPv4Address(max_ip))
            ip = int(ipaddress.IPv4Address(ip_address))
            if ip >= min_ip and ip <= max_ip:
                return True
        return False
    
    def validation_check(self, direction, protocol, port, ip):
        if direction not in ['inbound','outbound']:
            return False
        if protocol not in ['tcp', 'udp']:
            return False
        if port < 1 or port > 65535:
            return False
        try:
            ip = int(ipaddress.IPv4Address(ip))
        except:
            return False
        return True
    