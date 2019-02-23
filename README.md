# This is a POC 
## Client
A Saltstack client to sent commands from the master directly to the zmq port 4506 written in go.
Example : salt -L minion test.ping

## Event Listener (listener)
A Saltstack event listener listening for event from the unix socket.

## Salt-minion (Subscriber)
A Salstack minion that connects to the saltstack master and receives events.

## API
An HTTP api that recevies a request sends them to the minion and gives the response. 
