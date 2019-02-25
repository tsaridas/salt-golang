# This is a POC 

## Disclaimer
This is me trying to learn some golang and had the idea to write a salt client to begin with and I ended up writing a subscriber and api. This is not something that is intended for production usage but rather as an Proof of Concept. 

## Runnables
#### Event Listener
A Saltstack event listener listening for event from the unix socket. Needs to be ran a on salt master server.
```
go run eventlistener/event-listener.go
```

#### Client
A Saltstack client to sent commands from the master directly to the zmq port 4506 written in go.
salt.go : Will run a salt module to a minion. Needs to be ran from a salt master server.
```
Example : go run salt.go -L minion test.ping
```

#### API
An HTTP api that recevies a request sends them to the minion and gives the response. Will initialize a http api and ping the minion-id that you define. If minion does not return it will timeout and return the JID. Needs to be ran on a Salt Master server.
api/salt-api.go : 
```
go run salt-api.go
curl -Lv 127.0.0.1:8080/minion-id
```

#### Salt-minion
A Salstack minion that connects to the saltstack master and receives events. You need to use target type list or glob in order to target the minion and make sure the normal salt-minion is installed and has the keys generated. 
salt-minion/salt-minion.go : Will start a subscriber that connects to a salt master server. You need to define -id and --masterip in args.
```
Example: go run salt-minion.go -id salt-minion-01 --masterip 192.168.1.1
```

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
