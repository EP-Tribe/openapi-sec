package main

import (
	"fmt"
	"net/http"
	"os"
	"io/ioutil"
	"encoding/json"
    "strings"
	)

type Config struct {
    Url string `json:"url"`
    Ratelimit string `json:"ratelimit"`
    RatelimiteWhitelist string `json:"ratelimit_whitelist"`
    RestrictedEndpoints []RestrictedEndpoint `json:"restricted_endpoints"`
    WebServer string `json:"webserver"`
}

type RestrictedEndpoint struct {
    Path string `json:"path"`
    IpAllowed string `json:"ip_allowed"`
}

type Endpoint struct {
    Url string
    Methods []Method
}

type Method struct {
	Name string
	Parameters []EndpointParameter
}

type EndpointParameter struct {
    Name string `json:"name"`
    In string `json:"in"`
    Description string `json:"description"`
    Format string `json:"format"`
    Type string `json:"type"`
    Required bool `json:"required"`
    Enum []string `json:"enum"`
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
    var swaggerSpec interface{}
    json.Unmarshal(body, &swaggerSpec)
    return swaggerSpec
}

func getEndpointList(s map[string]interface{}) []Endpoint {
    var list []Endpoint
    for endpoint, availableMethods := range s["paths"].(map[string]interface{}) {
    	var methods []Method
    	var parameters []EndpointParameter
    	for method, description := range availableMethods.(map[string]interface{}){
    		for k, v := range description.(map[string]interface{}){
    			if k == "parameters" {
    				switch x := v.(type) {
						case []interface{}:
    						for _, e := range x {
        						var p EndpointParameter
        						s, _ := json.Marshal(e)
        						json.Unmarshal(s, &p)
        						parameters = append(parameters, p)
    						}
						default:
    						fmt.Printf("can't parse parameter %T\n", v)
					}
    			}
    		}
    		methods = append(methods, Method{method, parameters})
    	}
    	list = append(list, Endpoint{endpoint, methods})
    }
    return list
}

func generateRules(e []Endpoint, c Config ) []string {
    var rules []string
    var outputStyle string
    //var ratelimit string = c.Ratelimit
    if c.WebServer == "apache" || c.WebServer == "nginx" {
        outputStyle = c.WebServer
    } else {
        return rules
    }
    fmt.Println(outputStyle)
    rules = append(rules, generateLocationBlockHeader(e[10], outputStyle))
    return rules
}

func generateLocationBlockHeader(e Endpoint, s string) string{
    var locationBlockHeader string
    var url string
    if len(extractParamFromUrl(e.Url)) > 0 {
        paramaterTypeInUrl := getParameterType(e, extractParamFromUrl(e.Url))
        url = e.Url[0:strings.Index(e.Url, "{")] + typeToRegex(paramaterTypeInUrl) + e.Url[strings.Index(e.Url, "}")+1:]
        fmt.Println("url : ", url)
    } else {
        url = e.Url
    }
    if s == "apache" {
        locationBlockHeader = ""
    }
    return locationBlockHeader
}

func getParameterType(e Endpoint, p string) string {
    for _, method := range e.Methods {
        for _, parameter := range method.Parameters {
            if parameter.Name == p {
                return typeToRegex(parameter.Type)
            }
        }
    }
    return ""
}

func extractParamFromUrl (u string) string{
    if strings.ContainsAny("{", u) == false {
        return ""
    }
    return u[strings.Index(u, "{")+1:strings.Index(u, "}")]
}

func typeToRegex(t string) string{
    switch t {
    case "boolean":
        return "[0-1]"
    case "integer":
        return "[+-]?[0-9]*"
    case "number":
        return "[+-]?[0-9\\.,]*"
    case "string":
        return "[^/]*"
    default:
        return ""
    }
}

func main() {
	config := readConfigFile("C:\\Users\\joanelis\\Documents\\swagger-sec\\test2.json")
//    if len(os.Args) != 2 {
//        fmt.Fprintf(os.Stderr, "Usage: %s config.json\n", os.Args[0])
//        os.Exit(1)
//    }
//    config := readConfigFile(os.Args[1])
    swaggerSpecs := getSwaggerSpec(config.Url).(map[string]interface{})
    fmt.Println("Version of swagger specifications : ", swaggerSpecs["swagger"], "\nParsing its content...\n")
    endpoints := getEndpointList(swaggerSpecs)
    rules := generateRules(endpoints, config)
    fmt.Println(rules)
//    fmt.Println(endpoints)
//    for _, endpoint := range endpoints {
//    	fmt.Println("\nendpoint : ", endpoint.Url)
//    	for _, method := range endpoint.Methods {
//    		fmt.Println("\t\t", method.Name)
//    		fmt.Println("\t\t\tparameters : ")
//    		for _, parameter := range method.Parameters {
//    			var mappedParameters map[string]string
//    			p, _ := json.Marshal(parameter)
//    			json.Unmarshal(p, &mappedParameters)
//    			for k, v := range mappedParameters {
//    				if len(v) > 0 {
//    					fmt.Println("\t\t\t\t", k, " : ", v)
//    				}
//    			}
//    			fmt.Println("\n")
//    		}
//    	}
//    }
}