import random as rd
import ipaddress
from Firewall import Firewall

FW = Firewall('rules.csv')

# basic test cases
test_list = [['inbound', 'tcp', 80, '192.168.1.2'],
             ['inbound', 'udp', 53, '192.168.2.1'],
             ['outbound', 'tcp', 10234, '192.168.10.11'],
             ['inbound', 'tcp', 81, '192.168.1.2'],
             ['inbound', 'udp', 24, '52.12.48.92']]

# create random test cases
min_ip = int(ipaddress.IPv4Address('192.168.10.11'))
max_ip = int(ipaddress.IPv4Address('255.255.255.255'))
min_port, max_port = 10000, 20000
for i in range(5):
    if i % 2:
        # the result should be True
        test_list.append(['outbound', 'tcp', rd.randint(min_port, max_port), '192.168.10.11'])

    else:
        test_list.append(['outbound', 'udp', rd.randint(min_port, max_port), rd.randint(min_ip, max_ip)])

# Incorrect parameter test cases
test_list.append(['inbond', 'tcp', 80, '192.168.1.2'])
test_list.append(['inbound', 'tcb', 80, '192.168.1.2'])
test_list.append(['inbound', 'tcp', 123456, '192.168.1.2'])
test_list.append(['inbound', 'tcp', 80, '192.168.1.257'])

# test and print the result
cnt = 0
for t in test_list:
    if cnt == 0:
        print('basic test cases results:')
        print('The answer should be True, the result is also', )
    if cnt == 5:
        print('randomly create some test cases to test:')
    
    if cnt == 10:
        print('test invalid input network packet:')
    
    print(FW.accept_packet(t[0],t[1],t[2],t[3]))
    cnt += 1
