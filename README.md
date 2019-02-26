# This is a POC 

## Disclaimer
This is me trying to learn some golang and had the idea to write a salt client to begin with and I ended up writing a subscriber and api. This is not something that is intended for production usage but rather as an Proof of Concept. 

## Runnables
#### Event Listener
A Saltstack event listener listening for event from the unix socket. Needs to be ran a on salt master server.
```
[root@salt-master api]#go run eventlistener/event-listener.go
Tag is 15511887253592021111 and ret is map[_stamp:2019-02-26T13:45:25.361952 minions:[salt-minion-01]]

Tag is salt/job/15511887253592021111/new and ret is map[jid:15511887253592021111 user:root tgt:[salt-minion-01] arg:[] fun:test.ping tgt_type:list missing:[] _stamp:2019-02-26T13:45:25.363199 minions:[salt-minion-01]]

Tag is salt/job/15511887253592021111/ret/salt-minion-01 and ret is map[retcode:%!s(int8=0) success:%!s(bool=true) id:salt-minion-01 fun_args:[] jid:15511887253592021111 return:%!s(bool=true) cmd:_return _stamp:2019-02-26T13:45:25.495549 fun:test.ping]
```
```
[root@salt-master api]# salt -L salt-minion-01 test.ping
salt-minion-01:
    True
```

#### Client
A Saltstack client to sent commands from the master directly to the zmq port 4506 written in go.
salt-cli/salt.go : Will run a salt module to a minion. Needs to be ran from a salt master server.
```
[root@salt-master api]# go run salt.go -L minion test.ping
salt-minion-01:
   True
[root@salt-master salt-cli]# go run salt.go -L salt-minion-01 cmd.run 'ls'
salt-minion-01:
anaconda-ks.cfg
original-ks.cfg
```
As you can see the results are not formated the same way that the normal salt client does ( adds some spaces infront of the result on each line ).

#### Client-v2
A new version of Saltstack client to sent commands from the master directly to the zmq port 4506 written in go.
salt-cli/salt.go : Will run a salt module to a minion. Needs to be ran from a salt master server.
```
Example : go run salt.go -L minion test.ping
```

#### API
An HTTP api that recevies a request sends them to the minion and gives the response. Will initialize a http api and ping the minion-id that you define. If minion does not return it will timeout and return the JID. Needs to be ran on a Salt Master server. The API will wait 5 seconds to receive results and it will return false.
api/salt-api.go : 
```
[root@salt-master api]# go run salt-api.go
2019/02/26 13:38:14 Added tag salt/job/15511882940789845781/ret/salt-minion-01
2019/02/26 13:38:14 Found tag salt/job/15511882940789845781/ret/salt-minion-01
2019/02/26 13:38:06 Added tag salt/job/15511882869645707051/ret/salt-minion-02
2019/02/26 13:38:11 Timeout 15511882869645707051
```
```
[root@salt-master api]# time curl -Lv 127.0.0.1:8080/minion-id
true

real	0m0.125s
user	0m0.001s
sys	0m0.007s
[root@salt-master api]# time curl  127.0.0.1:8080/salt-minion-02
false

real	0m5.008s
user	0m0.001s
sys	0m0.006s
```

#### Salt-minion
A Salstack minion that connects to the saltstack master and receives events. You need to use target type list or glob in order to target the minion and make sure the normal salt-minion is installed and has the keys generated. 
salt-minion/salt-minion.go : Will start a subscriber that connects to a salt master server. You need to define -id and --masterip in args.
```
[root@salt-master api]# go run salt-minion.go -id salt-minion-01 --masterip 192.168.1.1
Authenticated with Master.
Subscribed to Master.
Got function : test.ping with jid map[user:root arg:[] fun:test.ping tgt_type:list jid:15511890084666866121 tgt:[salt-minion-02] ret:]
Replied to event : map[jid:15511890084666866121 tgt:[salt-minion-02] ret: user:root arg:[] fun:test.ping tgt_type:list]
```
The minion will only answer to test.ping requests.

## Requirements
```
yum install zeromq-devel -y
```

## Installation
```
go get github.com/tsaridas/salt-event-listener-golang
cd $GOPATH/src/github.com/tsaridas/salt-event-listener-golang
go get -d ./...
```

## Tested
This was tested on a Centos7.5 and salt-2018.3.3. It should work on lower and higher versions of Saltstack.

## Performance
With the go client
```
[root@salt-master salt-event-listener-golang]# time ./salt -L salt-minion-01 test.ping
salt-minion-01:
   True

real	0m0.030s
user	0m0.004s
sys	0m0.005s
```
With the python client
```
[root@salt-master salt-event-listener-golang]# time salt -L salt-minion-01 test.ping
salt-minion-01:
    True

real	0m0.909s
user	0m0.544s
sys	0m0.184s
```
