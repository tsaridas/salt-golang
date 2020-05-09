package config

import (
	"github.com/tsaridas/salt-golang/lib/utils"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

// Conf type config
type Conf struct {
	MasterIP string `yaml:"master"`
	MinionID string `yaml:"id"`
	Files    []string
}

func (c *Conf) getConf(f string) {
	filename, _ := filepath.Abs(f)
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		log.Println("Unmarshal failed with error: %v", err)
	}
}

func (c *Conf) getFiles() {
	saltConfig := "/etc/salt/"
	if file.Exists(saltConfig + "minion") {
		c.Files = append(c.Files, "/etc/salt/minion")
		log.Println("Loading config file:", c.Files[0])
	}
	saltConfigFolder := saltConfig + "minion.d/"
	f, _ := ioutil.ReadDir(saltConfigFolder)
	for _, file := range f {
		if !strings.HasPrefix(file.Name(), "_") && strings.HasSuffix(file.Name(), ".conf") {
			c.Files = append(c.Files, saltConfigFolder+file.Name())
			log.Println("Loading config file:", saltConfigFolder+file.Name())
		}
	}
}

// GetConfig from default minion dir
func GetConfig() (allConf Conf) {
	allConf.getFiles()
	for _, file := range allConf.Files {
		allConf.getConf(file)
	}
	return allConf
}
