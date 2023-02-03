module github.com/tsaridas/salt-golang

go 1.19

replace github.com/tsaridas/salt-golang => ./

require (
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pebbe/zmq4 v1.2.9
	github.com/ryanuber/go-glob v1.0.0
	github.com/tsaridas/salt-golang v0.0.0-00010101000000-000000000000
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/golang/protobuf v1.3.1 // indirect
	golang.org/x/net v0.0.0-20190603091049-60506f45cf65 // indirect
	google.golang.org/appengine v1.6.7 // indirect
)
