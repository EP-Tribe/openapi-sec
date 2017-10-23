package main

import (
	"fmt"
	"net/http"
	"os"
	"io/ioutil"
	"encoding/json"
	)

type RestrictedEndpoint struct {
    Path string `json:"path"`
    IpAllowed string `json:"ip_allowed"`
}

type Config struct {
    Url string `json:"url"`
    Ratelimit string `json:"ratelimit"`
    RatelimiteWhitelist string `json:"ratelimit_whitelist"`
    RestrictedEndpoints []RestrictedEndpoint `json:"restricted_endpoints"`
}

type Endpoint struct {
    Url string
    Methods []string
}

type EndpointMethodConf struct {
    Summary string `json:"summary"`
}

func toJson(p interface{}) string {
    bytes, err := json.Marshal(p)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    return string(bytes)
}

func readConfigFile(s string) Config {
    configFile, err := os.Open(s)
    defer configFile.Close()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Err : unable to read %s\n", s)
        os.Exit(1)
    }
    bytes, _ := ioutil.ReadAll(configFile)
    var config Config
    json.Unmarshal(bytes, &config)
    return config
}

func getSwaggerSpec(s string) interface{} {
    response, err := http.Get(s)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Err : unable to download %s\n", s)
        os.Exit(1)
    }
    body, err := ioutil.ReadAll(response.Body)
//    var swaggerSpec SwaggerSpec
    var swaggerSpec interface{}
    json.Unmarshal(body, &swaggerSpec)
    return swaggerSpec
}

func getEndpointList(s map[string]interface{}) []Endpoint {
    var list []Endpoint
    //list.Endpoints[0].Url = "test"
    for k1, v1 := range s {
        if k1 == "paths" { 
            for k2, v2 := range v1.(map[string]interface{}) {
                var methods []string
                for k3, _ := range v2.(map[string]interface{}) {
                    methods = append(methods, k3)
                }
                list = append(list, Endpoint{k2, methods })   
            }
        }

    }
    return list
}

func main() {
//    if len(os.Args) != 2 {
        config := readConfigFile("C:\\Users\\joanelis\\Desktop\\tools\\GoSecGen\\test2.json")
//        fmt.Fprintf(os.Stderr, "Usage: %s config.json\n", os.Args[0])
//        os.Exit(1)
//    }
//    config := readConfigFile(os.Args[1])
    swaggerSpecs := getSwaggerSpec(config.Url).(map[string]interface{})
    fmt.Println("Version of swagger specifications : ", swaggerSpecs["swagger"], "\nParsing its content...\n")
    fmt.Println(getEndpointList(swaggerSpecs))
}