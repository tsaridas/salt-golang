# This is a POC 

## Disclaimer
This is me trying to learn some golang and had the idea to write a salt client to begin with and I ended up writing a subscriber and api. This is not something that is intended for production usage but rather as an Proof of Concept. 

## Client
A Saltstack client to sent commands from the master directly to the zmq port 4506 written in go.


## Event Listener (listener)
A Saltstack event listener listening for event from the unix socket.

## Salt-minion (Subscriber)
A Salstack minion that connects to the saltstack master and receives events. This only prints events and does not respond.

## API
An HTTP api that recevies a request sends them to the minion and gives the response. 

## Main classes
api-event-listener.go : Will initialize an event listener. Needs to be ran a on salt master server.

salt.go : Will run a salt command to a minion. Needs to be ran from a salt master server.
```
Example : go run salt.go -L minion test.ping
```

api/main.go : Will initialize a http api. Needs to be ran on a salt master server.

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
```

## Tested
This was tested on a Centos7.5 and salt-2018.3.3. It should work on lower and higher versions of Saltstack.
