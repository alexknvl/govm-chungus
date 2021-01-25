package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// DataInfo data info
type DataInfo struct {
	AppName    string `json:"app_name,omitempty"`
	StructName string `json:"struct_name,omitempty"`
	IsDBData   bool   `json:"is_db_data,omitempty"`
	Key        string `json:"key,omitempty"`
	Value      string `json:"value,omitempty"`
	Life       uint64 `json:"life,omitempty"`
}

func isMiner(chain uint64, server, addr string) bool {
	urlStr := fmt.Sprintf("http://%s/api/v1/%d/data", server, chain)
	urlStr += "?app_name=ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	urlStr += "&is_db_data=true&struct_name=dbMiner&key=" + addr
	resp, err := http.Get(urlStr)
	if err != nil {
		log.Println("fail to get miner info:", server, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var info DataInfo
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	json.Unmarshal(data, &info)
	if info.Value != "" {
		return true
	}

	return false

}
