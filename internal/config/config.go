package config

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type IPService struct {
	IPs []string `yaml:"ips"`
}

type HTTPService struct {
	IPs []string `yaml:"ips"`
}

type Config struct {
	InterestingIPServices   map[string]IPService   `yaml:"ip_services"`
	InterestingHTTPServices map[string]HTTPService `yaml:"http_services"`
	InterestingUsersPrefix  string                 `yaml:"interesting_users_prefix"`
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

func GetIPToService(config Config) map[string]string {
	ipToService := make(map[string]string)
	for serviceName, service := range config.InterestingIPServices {
		for _, ip := range service.IPs {
			ipToService[ip] = serviceName
		}
	}
	for serviceName, service := range config.InterestingHTTPServices {
		for _, ip := range service.IPs {
			ipToService[ip] = serviceName
		}
	}
	return ipToService
}

func ConfigToBPFFilter(config Config) string {
	//bpfFilter := "((tcp and tcp[tcpflags] & tcp-syn != 0) or udp) and ("
	bpfFilter := "(tcp or udp) and ("
	firstFilter := true
	for _, service := range config.InterestingIPServices {
		for _, ip := range service.IPs {
			if firstFilter {
				bpfFilter += "dst host " + ip
				firstFilter = false
			} else {
				bpfFilter += " or dst host " + ip
			}
		}
	}
	for _, service := range config.InterestingHTTPServices {
		for _, ip := range service.IPs {
			if firstFilter {
				bpfFilter += "dst host " + ip
				firstFilter = false
			} else {
				bpfFilter += " or dst host " + ip
			}
		}
	}
	bpfFilter += ")"
	return bpfFilter
}
