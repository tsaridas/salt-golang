package main

import "os/exec"

func Run(argument []interface{}) (r string, err error) {
	cmd := argument[0].(string)
	out, _ := exec.Command("/bin/sh", "-c", cmd).Output()
	r = string(out)
	return
}
