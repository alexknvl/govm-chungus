package main

import (
	"bytes"
	"container/list"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	// "io/ioutil"

	"github.com/lengzhao/govm/wallet"
	// "github.com/alexknvl/secp256k1-go/secp256k1"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/websocket"
	// "crypto/ecdsa"
)

const (
	// HashLen the byte length of Hash
	HashLen = 32
	// AddressLen the byte length of Address
	AddressLen = 24
)

// Hash The KEY of the block of transaction
type Hash [HashLen]byte

// Address the wallet address
type Address [AddressLen]byte

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

func max(x, y uint64) uint64 {
	if x > y {
		return x
	}
	return y
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Empty Check whether Hash is empty
func (h Hash) Empty() bool {
	return h == (Hash{})
}

// MarshalJSON marshal by base64
func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h[:])
}

// UnmarshalJSON UnmarshalJSON
func (h *Hash) UnmarshalJSON(b []byte) error {
	var v []byte
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	copy(h[:], v)
	return nil
}

// Empty Check where Address is empty
func (a Address) Empty() bool {
	return a == (Address{})
}

// MarshalJSON marshal by base64
func (a Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(a[:])
}

// UnmarshalJSON UnmarshalJSON
func (a *Address) UnmarshalJSON(b []byte) error {
	var v []byte
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	copy(a[:], v)
	return nil
}

// Block Block structure
type Block struct {
	//signLen	  uint8
	//sign	      []byte
	Time          uint64
	Previous      Hash
	Parent        Hash
	LeftChild     Hash
	RightChild    Hash
	TransListHash Hash
	Producer      Address
	Chain         uint64
	Index         uint64
	Nonce         uint64
}

// RespBlock Block
type RespBlock struct {
	Block
	HashpowerLimit uint64
	From           string
}

type RespBlockWithKey struct {
	Block
	HashpowerLimit uint64
	From           string

	Key []byte
	Dev bool
}

var blocks map[uint64]*RespBlockWithKey
var mu sync.Mutex
var hashPowerItem map[int64]uint64
var genBlockNum uint64
var confirmedBlockNum uint64
var blockFlag int
var secp256k1_Context *Context

type HashRateElem struct {
	Hashes   uint64
	Duration uint64
	Time     uint64
}

var recentBlockQueue *list.List

func init() {
	ctx, err := ContextCreate(ContextSign)
	if err != nil {
		log.Panicln(err)
		// return nil
	}
	secp256k1_Context = ctx
	blocks = make(map[uint64]*RespBlockWithKey)
	rand.Seed(time.Now().UnixNano())
	hashPowerItem = make(map[int64]uint64)
	recentBlockQueue = list.New()

	// ContextDestroy(ctx)
}

func unsafeComputeHashrate() (uint64, uint64, uint64, float64) {
	now := time.Now().Unix() / 60
	var hashes uint64
	var count uint64

	var first int64
	for i := now - 120; i <= now; i++ {
		if hashPowerItem[i] > 0 {
			first = i
			break
		}
	}

	var last int64
	for i := now; i >= now-120; i-- {
		if hashPowerItem[i] > 0 {
			last = i
			break
		}
	}

	for i := first + 1; i <= last-1; i++ {
		hashes += hashPowerItem[i]
		count++
	}

	var rate float64
	if genBlockNum == 0 {
		rate = 0.0
	} else {
		rate = (float64(confirmedBlockNum) / float64(genBlockNum)) * 100.0
	}

	var hashRate uint64
	if count > 0 {
		hashRate = hashes / count
	} else {
		hashRate = 0
	}

	return hashRate, genBlockNum, confirmedBlockNum, rate
}

func showHashPower() {
	mu.Lock()
	hashRate, genBlockNum, confirmedBlockNum, confirmationRate := unsafeComputeHashrate()
	mu.Unlock()

	fmt.Printf("hashrate=%d, candidates=%d, confirmed=%d (%.1f%%)\n", hashRate, genBlockNum, confirmedBlockNum, confirmationRate)

	for _, c := range conf.Chains {
		val := getDataFromServer(c, conf.Servers[0], "", "statMining", userAddrStr)
		var count uint64
		if len(val) > 0 {
			Decode(val, &count)
		}
		fmt.Printf("chain:%d, successful mining blocks:%d\n", c, count)
	}
}

type wsHead struct {
	Addr Address
	Time int64
}

func requestBlock(chain uint64, servers chan string) {
	server := <-servers
	defer func(s string) {
		err := recover()
		if err != nil {
			log.Println("recover:request block,", err)
		}
		servers <- s
		time.Sleep(time.Second * 5)
		log.Printf("chain:%d, disconnected from server: %s\n", chain, server)
		go requestBlock(chain, servers)
	}(server)

	origin := fmt.Sprintf("http://%s", server)
	url := fmt.Sprintf("ws://%s/api/v1/%d/ws/mining", server, chain)
	ws, err := websocket.Dial(url, "", origin)
	if err != nil {
		log.Println("Failed to connect to a server: ", server, err)
		return
	}
	defer ws.Close()

	head := wsHead{}
	// priv1 := wallet.NewPrivateKey()
	//pub1 := wallet.GetPublicKey(priv1)
	Decode(userAddress, &head.Addr)
	head.Time = time.Now().Unix()
	data := Encode(head)
	sign := wallet.Sign(userKey, data)
	data = append(data, sign...)
	_, err = ws.Write(data)
	if err != nil {
		log.Println("send msg error:", err)
		return
	}
	fmt.Printf("chain:%d, connected to a server: %s\n", chain, server)

	for {
		t := time.Now().Add(time.Minute * 2)
		ws.SetReadDeadline(t)

		var blockRaw RespBlock
		err = websocket.JSON.Receive(ws, &blockRaw)
		if err != nil {
			break
		}

		var block RespBlockWithKey
		block.Block = blockRaw.Block
		block.HashpowerLimit = blockRaw.HashpowerLimit
		block.From = server

		// Decide on the account to use:
		if block.Index%4 == 0 {
			Decode(devAddress, &block.Producer)
			block.Key = devKey
			block.Dev = true
		} else {
			Decode(userAddress, &block.Producer)
			block.Key = userKey
			block.Dev = false
		}

		mu.Lock()
		if blocks[block.Chain] == nil || blocks[block.Chain].Index < block.Index {
			blocks[block.Chain] = &block
			blockFlag++

			confirmed := false
			for e := recentBlockQueue.Front(); e != nil; e = e.Next() {
				value := e.Value.([]byte)
				if bytes.Equal(value, block.Previous[0:len(block.Previous)]) {
					confirmed = true
				}
			}

			var msg string
			if confirmed {
				confirmedBlockNum += 1
				msg = "(CONFIRMED)"
			} else {
				msg = ""
			}
			if conf.Verbosity >= 3 {
				hashRate, genBlockNum, confirmedBlockNum, confirmationRate := unsafeComputeHashrate()
				log.Printf("new_block hr=%d, cc=%d, cf=%d (%.1f%%) from:%s chain:%d index:%d hpl:%d previous:%x...  %s\n",
					hashRate, genBlockNum, confirmedBlockNum, confirmationRate,
					block.From, block.Chain, block.Index, block.HashpowerLimit, block.Previous[:8], msg)
			}
		}
		mu.Unlock()
	}
}

func postBlock(chain uint64, server string, key, data []byte) {
	broadcast := "true"
	urlStr := fmt.Sprintf("http://%s/api/v1/%d/data?key=%x&broadcast=%s", server, chain, key, broadcast)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewBuffer(data))
	if err != nil {
		log.Println("Failed to create a new request: ", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Failed to make a requst: ", err)
		return
	}

	if conf.Verbosity >= 4 {
		log.Printf("Response status from %s: %s", server, resp.Status)
	}
	resp.Body.Close()
}

func updateBlock() {
	for _, c := range conf.Chains {
		servers := make(chan string, len(conf.Servers))
		for _, server := range conf.Servers {
			servers <- server
		}
		for i := 0; i < conf.KeepConnServerNum; i++ {
			go requestBlock(c, servers)
		}
	}
}

func doMining() {
	for _, chain := range conf.Chains {
		for i := 0; i < conf.ThreadNumber; i++ {
			go func(c uint64, thread int) {
				for {
					mu.Lock()
					block := blocks[c]
					mu.Unlock()
					if block == nil {
						time.Sleep(1 * time.Second)
						continue
					}
					miner(thread, block)
				}
			}(chain, i)
		}
	}
}

const VerifyBlocks = true

func miner(thread int, in *RespBlockWithKey) {
	/* start := time.Now().Unix()
	if start > 1602720000 { // Oct 05
		return
	} */
	/* if in.Time+80 < uint64(start) {
		time.Sleep(1 * time.Second)
		return
	} */

	var block = *in
	block.Nonce = rand.Uint64()
	if conf.Verbosity >= 4 {
		log.Printf("mining dev:%t thread:%d from:%s chain:%d index:%d", block.Dev, thread, block.From, block.Chain, block.Index)
	}

	var count uint64
	oldFlag := blockFlag

	var increment uint64
	if conf.ChunkHashes > 0 {
		increment = uint64(conf.ChunkHashes)
	} else {
		increment = 256
	}

	for {
		if oldFlag != blockFlag {
			mu.Lock()

			if blocks[block.Chain] != nil && blocks[block.Chain].Index != block.Index {
				now := time.Now().Unix()
				id := now / 60
				hashPowerItem[id] += count
				mu.Unlock()
				break
			} else {
				oldFlag = blockFlag
				mu.Unlock()
			}
		}
		if conf.Sleep > 0 {
			time.Sleep(time.Millisecond * time.Duration(conf.Sleep))
		}
		count += increment
		block.Nonce += increment

		data := Encode(block.Block)
		// sign := Sign(block.Key, data)
		// // sign2 := wallet.Sign(block.Key, data)
		// // log.Printf("original : %x\n", sign2)
		// // log.Printf("new      : %x\n", sign)

		// var val = []byte{wallet.SignLen}
		// val = append(val, sign...)
		// val = append(val, data...)
		// key := wallet.GetHash(val)
		// // key_new := GovmSha3(val)
		// // log.Printf("original : %x\n", key)
		// // log.Printf("new      : %x\n", key_new)

		// log.Printf("wtf00\n")
		val, key, nonce := GovmSolveMany(secp256k1_Context, data, block.Key, increment)

		// block.Nonce = nonce
		// data = Encode(block.Block)
		// val2, key2 := GovmSolveOne(secp256k1_Context, data, block.Key)
		// log.Printf("val : %x : %x\n", val, val2)
		// log.Printf("key : %x : %x\n", key, key2)

		// log.Printf("old: %d, new: %d\n", getHashPower(key), GovmHashPower(key))

		if getHashPower(key) >= block.HashpowerLimit {
			if conf.Verbosity >= 3 {
				log.Printf("found_candidate dev:%t from:%s chain:%d key:%x\n", block.Dev, block.From, block.Chain, key)
			}

			if VerifyBlocks {
				block.Nonce = nonce
				data1 := Encode(block.Block)
				sign1 := wallet.Sign(block.Key, data1)
				var val1 = []byte{wallet.SignLen}
				val1 = append(val1, sign1...)
				val1 = append(val1, data1...)
				key1 := wallet.GetHash(val1)

				if !bytes.Equal(key, key1) {
					log.Printf("val : %x : %x\n", val, val1)
					log.Printf("key : %x : %x\n", key, key1)
					log.Panicf("verification failed!")
				}
			}

			mu.Lock()

			now := time.Now().Unix()
			id := now / 60
			hashPowerItem[id] += count

			if !block.Dev {
				genBlockNum++
				if recentBlockQueue.Len() >= 10 {
					recentBlockQueue.Remove(recentBlockQueue.Front())
				}
				recentBlockQueue.PushBack(key)
			}
			mu.Unlock()

			postBlock(block.Chain, block.From, key, val)
			break
		}
	}
}

func getHashPower(in []byte) uint64 {
	var out uint64
	for _, item := range in {
		out += 8
		if item != 0 {
			for item > 0 {
				out--
				item = item >> 1
			}
			return out
		}
	}
	return out
}

var hashPrefix = []byte("govm")

// GetHash get data hash
func GetHash(in []byte) []byte {
	sha := sha3.New256()
	if len(hashPrefix) > 0 {
		sha.Write(hashPrefix)
	}
	sha.Write(in)
	return sha.Sum(nil)
}

const (
	// AddressLength address length
	AddressLength = 24
	// SignLen default length of sign
	SignLen       = 65
	publicKeyLen  = 33
	privateKeyLen = 32
	// TimeDuration EAddrTypeIBS的子私钥有效时间,一个月
	TimeDuration = 31558150000 / 12
)

// Sign 用私钥对msg进行签名
func Sign(privK, msg []byte) []byte {
	msgH := wallet.GetHash(msg)
	if len(privK) != privateKeyLen {
		return nil
	}

	// privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privK)
	// signature, err := btcec.SignCompact(btcec.S256(), privKey, msgH, true)

	_, sig, err := EcdsaSignRecoverable(secp256k1_Context, msgH, privK)
	if err != nil {
		log.Println(err)
		return nil
	}

	_, signature, _, err := EcdsaRecoverableSignatureSerializeCompact1(secp256k1_Context, sig)
	if err != nil {
		log.Println(err)
		return nil
	}

	//log.Printf("sign length:%d,hash:%x\n", len(msg), msgH)

	return signature
}
