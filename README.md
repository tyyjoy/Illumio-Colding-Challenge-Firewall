# Illumio-Colding-Challenge-Firewall

## Testing:
* First, I tested the five provided test cases;
* Second, I created five test cases, some of them match the rules(should return True) and some might not(randomly created);
* Third, I tested four test cases that the network packet has some paramter that is invalid.

## My Designs:
* In order to make the cold work "reasonably quickly" with so many rules to check, first I think I need to implement by hashmap(dictionary in python);
* If creat a hashmap by use of all the rules(including the ones whithin the ranges) as the key, it will be at most 2^52 number of posibile keys, which cost to much space; To make tradeoffs, I used the string combination of the first three parameters as the keys, which at most have 2^20 number of keys, which I think is accpetable, with value is a dictionary.
* For the nested dictionary, I created a set to store those ip-address paramters which whithout a range, and a list to store the ones come with a range.
* When new network packet comes, it will take O(1) to check if it can matches the first three parameters; and O(k) to check if it matches a valid ip address in the rules(k is the length of # ip address range in rules)

## My Designs:
If I have more time, I want to:
* First, create more test cases to make sure the algorithm does work;
* Second, figure out a method that can lower the time complexity of accept_packet check method, or make use of the binary search since there exists ranges.

## How to test this code (`test.py`)

From the `FirewallCodingChallenge/` directory, run the following command in the terminal
```
$ python test.py
```

## Interests of the particular area:
* 1. Data team
* 2. Platform team
* 3. Policy team
