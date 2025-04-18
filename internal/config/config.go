package config

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	HttpServiceRegexes     []string          `yaml:"http_service_regexes"`
	IpsToServiceMap        map[string]string `yaml:"ips_to_service"`
	IpsToListenTo          []string          `yaml:"ips_to_listen_to"`
	InterestingUsersPrefix string            `yaml:"interesting_users_prefix"`
}

func ReadConfig(configPath string) (Config, error) {
	config := Config{}
	// this is deprecated but we have golang go1.11.6 in prod hosts, replace with os.ReadFile once we get on >1.16
	rawConfig, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error(err)
		return config, err
	}

	err = yaml.Unmarshal(rawConfig, &config)
	if err != nil {
		log.Error(err)
		return config, err
	}

	return config, nil
}

func ConfigToBPFFilter(config Config) string {
	//bpfFilter := "((tcp and tcp[tcpflags] & tcp-syn != 0) or udp) and ("
	// Only tcp http connections for now
	bpfFilter := "tcp and ("
	firstFilter := true
	for _, ip := range config.IpsToListenTo {
		if firstFilter {
			bpfFilter += "dst host " + ip
			firstFilter = false
		} else {
			bpfFilter += " or dst host " + ip
		}
	}
	bpfFilter += ")"
	return bpfFilter
}
