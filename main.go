package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/lengzhao/govm/wallet"
)

// Config config
type Config struct {
	WalletFile        string   `json:"wallet_file,omitempty"`
	Password          string   `json:"password,omitempty"`
	Servers           []string `json:"servers,omitempty"`
	ThreadNumber      int      `json:"thread_number,omitempty"`
	ChunkHashes       uint     `json:"chunk_hashes,omitempty"`
	Sleep             uint64   `json:"chunk_sleep_msec,omitempty"`
	Chains            []uint64 `json:"chains,omitempty"`
	KeepConnServerNum int      `json:"keep_conn_server_num,omitempty"`
	Verbosity         uint     `json:"verbosity,omitempty"`
}

const version = "v0.5.3"

var conf Config

var wal wallet.TWallet

var devAddrStr string
var devAddress []byte
var devKey []byte

var userAddrStr string
var userAddress []byte
var userKey []byte

func loadConfig(fileName string) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Println("fail to read configure.", err)
		os.Exit(2)
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		log.Println("fail to Unmarshal configure.", err)
		os.Exit(2)
	}
	if len(conf.Servers) == 0 {
		log.Println("server list is empty")
		os.Exit(2)
	}
}

// loadWallet load wallet
func loadWallet(fileName, password string, mustExist bool) {
	var err error
	if _, err = os.Stat(fileName); !os.IsNotExist(err) {
		wal, err = wallet.LoadWallet(fileName, password)
		if err != nil {
			fmt.Printf("invalid password for %s\n", fileName)
			os.Exit(-1)
		}
	} else {
		if mustExist {
			fmt.Printf("wallet %s not found\n", fileName)
			os.Exit(-1)
		} else {
			wal.Key = wallet.NewPrivateKey()
			pubKey := wallet.GetPublicKey(wal.Key)
			wal.Address = wallet.PublicKeyToAddress(pubKey, wallet.EAddrTypeDefault)
			wallet.SaveWallet(fileName, password, wal.Address, wal.Key, wal.SignPrefix)
		}
	}
	fmt.Printf("wallet %s: %x\n", fileName, wal.Address)
}

const InternalUseOnly = true

func main() {
	if InternalUseOnly {
		var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
		var dev = flag.String("dev", "", "make a dev profile")
		flag.Parse()

		if *cpuprofile != "" {
			f, err := os.Create(*cpuprofile)
			if err != nil {
				log.Fatal(err)
			}
			pprof.StartCPUProfile(f)
			fmt.Println("profiling:", cpuprofile)
			defer pprof.StopCPUProfile()
		}

		if *dev != "" {
			fileName := fmt.Sprintf("wallet.%s.key", *dev)
			wal.Key = wallet.NewPrivateKey()
			pubKey := wallet.GetPublicKey(wal.Key)
			wal.Address = wallet.PublicKeyToAddress(pubKey, wallet.EAddrTypeDefault)
			wallet.SaveWallet(fileName, "ERROR, %s is not a miner on chain %d\n\x00", wal.Address, wal.Key, wal.SignPrefix)
			os.Exit(0)
		}
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	fmt.Println("version of govm mining:", version)

	loadConfig("./conf.json")

	if !InternalUseOnly {
		loadWallet("wallet.dev.key", "ERROR, %s is not a miner on chain %d\n\x00", true)
		devKey = wal.Key
		devAddress = wal.Address
	}

	loadWallet(conf.WalletFile, conf.Password, false)
	userKey = wal.Key
	userAddress = wal.Address

	if InternalUseOnly {
		devKey = wal.Key
		devAddress = wal.Address
	}

	devAddrStr = hex.EncodeToString(devAddress)
	userAddrStr = hex.EncodeToString(userAddress)

	for _, chain := range conf.Chains {
		if !isMiner(chain, conf.Servers[0], devAddrStr) {
			log.Fatalf("ERROR, %s (DEV) is not a miner on chain %d\n", devAddrStr, chain)
			os.Exit(-1)
		}
		time.Sleep(1 * time.Second)
		if !isMiner(chain, conf.Servers[0], userAddrStr) {
			log.Fatalf("ERROR, %s is not a miner on chain %d\n", userAddrStr, chain)
			os.Exit(-1)
		}
		time.Sleep(1 * time.Second)
	}

	fmt.Println("                                                                                   ''''''")
	fmt.Println(" BBBBBBBBBBBBBBBBB     iiii                                OOOOOOOOO     lllllll  '::::'        ⣧     ⣿")
	fmt.Println(" B::::::::::::::::B   i::::i                             OO:::::::::OO   l:::::l  '::::'       ⢀⣿⣧   ⢰⡿⡇")
	fmt.Println(" B::::::BBBBBB:::::B   iiii                            OO:::::::::::::OO l:::::l  ':::''       ⢸⣿⡟⡆  ⣿⡇⢻")
	fmt.Println(" BB:::::B     B:::::B                                 O:::::::OOO:::::::Ol:::::l ':::'         ⢸⣿ ⣿ ⢰⣿⡇⢸")
	fmt.Println("   B::::B     B:::::Biiiiiii    ggggggggg   ggggg     O::::::O   O::::::O l::::l ''''          ⢸⣿⡄⢸ ⢸⣿⡇⢸")
	fmt.Println("   B::::B     B:::::Bi:::::i   g:::::::::ggg::::g     O:::::O     O:::::O l::::l               ⠘⣿⡇⢸⡄⠸⣿⡇⣿")
	fmt.Println("   B::::BBBBBB:::::B  i::::i  g:::::::::::::::::g     O:::::O     O:::::O l::::l                ⢿⣿⢸⡅ ⣿⢠⡏")
	fmt.Println("   B:::::::::::::BB   i::::i g::::::ggggg::::::gg     O:::::O     O:::::O l::::l                ⠈⣿⣿⣥⣾⣿⣿")
	fmt.Println("   B::::BBBBBB:::::B  i::::i g:::::g     g:::::g      O:::::O     O:::::O l::::l                 ⣿⣿⣿⣿⣿⣿⣿⣆")
	fmt.Println("   B::::B     B:::::B i::::i g:::::g     g:::::g      O:::::O     O:::::O l::::l                ⢸⣿⣿⣿⡿⡿⣿⣿⡿⡅")
	fmt.Println("   B::::B     B:::::B i::::i g:::::g     g:::::g      O:::::O     O:::::O l::::l                ⢸⠉ ⠉⡙⢔⠛⣟⢋⠦⢵")
	fmt.Println("   B::::B     B:::::B i::::i g::::::g    g:::::g      O::::::O   O::::::O l::::l                ⣾⣄  ⠁⣿⣯⡥⠃ ⢳")
	fmt.Println(" BB:::::BBBBBB::::::Bi::::::ig:::::::ggggg:::::g      O:::::::OOO:::::::Ol::::::l             ⢀⣴⣿⡇   ⠐⠠⠊⢀ ⢸")
	fmt.Println(" B:::::::::::::::::B i::::::i g::::::::::::::::g       OO:::::::::::::OO l::::::l          ⢀⣴⣿⣿⣿⡿     ⠈⠁  ⠘⣿⣄")
	fmt.Println(" B::::::::::::::::B  i::::::i  gg::::::::::::::g         OO:::::::::OO   l::::::l        ⣠⣿⣿⣿⣿⣿⡟           ⠈⣿⣷⡀")
	fmt.Println(" BBBBBBBBBBBBBBBBB   iiiiiiii    gggggggg::::::g           OOOOOOOOO     llllllll       ⣾⣿⣿⣿⣿⣿⠋             ⠈⣿⣿⣧")
	fmt.Println("                                         g:::::g                                       ⡜⣭⠤⢍⣿⡟                ⢸⢛⢭⣗")
	fmt.Println("                             gggggg      g:::::g                                       ⠁⠈  ⣀⠝               ⠄⠠  ⠰⡅")
	fmt.Println("                            g:::::gg   gg:::::g                                        ⢀  ⡀⠡                 ⠁⠔⠠⡕")
	fmt.Println("                            g::::::ggg:::::::g                                          ⣿⣷⣶⠒⠁                ⢰")
	fmt.Println("                             gg:::::::::::::g                                           ⠘⣿⣿⡇                ⠰")
	fmt.Println("        CCCCCCCCCCCCChhhhhhh   ggg::::::ggg                                              ⠈⢿⣿⣦             ⢠⠊⠉⢆")
	fmt.Println("     CCC::::::::::::Ch:::::h     gggggg                                              ⢀⠤  ⢤⣤⣽⣿⣿⣦⣀⢀⡠⢤⡤⠄ ⠒ ⠁   ⢘⠔")
	fmt.Println("   CC:::::::::::::::Ch:::::h                                                           ⡐⠈⠁⠈⠛⣛⠿⠟⠑⠈")
	fmt.Println("  C:::::CCCCCCCC::::Ch:::::h                                                          ⠉⠑⠒ ⠁")
	fmt.Println(" C:::::C       CCCCCC h::::h hhhhh       uuuuuu    uuuuuunnnn  nnnnnnnn       ggggggggg   ggggguuuuuu    uuuuuu      ssssssssss")
	fmt.Println("C:::::C               h::::hh:::::hhh    u::::u    u::::un:::nn::::::::nn    g:::::::::ggg::::gu::::u    u::::u    ss::::::::::s")
	fmt.Println("C:::::C               h::::::::::::::hh  u::::u    u::::un::::::::::::::nn  g:::::::::::::::::gu::::u    u::::u  ss:::::::::::::s")
	fmt.Println("C:::::C               h:::::::hhh::::::h u::::u    u::::unn:::::::::::::::ng::::::ggggg::::::ggu::::u    u::::u  s::::::ssss:::::s")
	fmt.Println("C:::::C               h::::::h   h::::::hu::::u    u::::u  n:::::nnnn:::::ng:::::g     g:::::g u::::u    u::::u   s:::::s  ssssss")
	fmt.Println("C:::::C               h:::::h     h:::::hu::::u    u::::u  n::::n    n::::ng:::::g     g:::::g u::::u    u::::u     s::::::s")
	fmt.Println("C:::::C               h:::::h     h:::::hu::::u    u::::u  n::::n    n::::ng:::::g     g:::::g u::::u    u::::u        s::::::s")
	fmt.Println(" C:::::C       CCCCCC h:::::h     h:::::hu:::::uuuu:::::u  n::::n    n::::ng::::::g    g:::::g u:::::uuuu:::::u  ssssss   s:::::s")
	fmt.Println("  C:::::CCCCCCCC::::C h:::::h     h:::::hu:::::::::::::::uun::::n    n::::ng:::::::ggggg:::::g u:::::::::::::::uus:::::ssss::::::s")
	fmt.Println("   CC:::::::::::::::C h:::::h     h:::::h u:::::::::::::::un::::n    n::::n g::::::::::::::::g  u:::::::::::::::us::::::::::::::s")
	fmt.Println("     CCC::::::::::::C h:::::h     h:::::h  uu::::::::uu:::un::::n    n::::n  gg::::::::::::::g   uu::::::::uu:::u s:::::::::::ss")
	fmt.Println("        CCCCCCCCCCCCC hhhhhhh     hhhhhhh    uuuuuuuu  uuuunnnnnn    nnnnnn    gggggggg::::::g     uuuuuuuu  uuuu  sssssssssss")
	fmt.Println("                                                                                       g:::::g")
	fmt.Println("                                                                           gggggg      g:::::g")
	fmt.Println("                                                                           g:::::gg   gg:::::g")
	fmt.Println("                                                                            g::::::ggg:::::::g")
	fmt.Println("                                                                             gg:::::::::::::g")
	fmt.Println("                                                                               ggg::::::ggg")
	fmt.Println("                                                                                  gggggg")
	fmt.Println("")
	fmt.Println("")

	updateBlock()
	doMining()

	var cmd string
	var descList = []string{
		"nil",
		"show HashPower",
		"show block for mining",
		"show wallet address",
		"show private key of wallet",
		"enter private key of wallet",
		"show balance",
		"is miner",
		"quit",
	}
	for {
		ops, _ := strconv.ParseInt(cmd, 10, 32)
		switch ops {
		case 1:
			showHashPower()
		case 2:
			mu.Lock()
			for c, block := range blocks {
				if block == nil {
					continue
				}
				fmt.Printf("chain:%d,index:%d,hp:%d,mp:30,previous:%x\n",
					c, block.Index, block.HashpowerLimit, block.Previous)
			}
			mu.Unlock()
		case 3:
			fmt.Printf("wallet: %x\n", userAddress)
		case 4:
			fmt.Printf("Private key: %x\n", userKey)
		case 5:
			fmt.Println("DISABLED")
		case 6:
			for _, c := range conf.Chains {
				val := getDataFromServer(c, conf.Servers[0], "", "dbCoin", userAddrStr)
				var coins uint64
				if len(val) > 0 {
					Decode(val, &coins)
				}
				fmt.Printf("chain:%d, balance:%.3f govm\n", c, float64(coins)/1000000000)
			}
		case 7:
			for _, c := range conf.Chains {
				if isMiner(c, conf.Servers[0], userAddrStr) {
					fmt.Printf("chain:%d, is a miner\n", c)
				} else {
					fmt.Printf("waring. chain:%d, not a miner\n", c)
				}
			}
		case 8:
			fmt.Println("exiting")
			time.Sleep(time.Second)
			if InternalUseOnly {
				pprof.StopCPUProfile()
			}
			os.Exit(0)
		default:
			fmt.Println("Please enter the operation number")
			for i, it := range descList {
				if i == 0 {
					continue
				}
				fmt.Printf("  %d: %s\n", i, it)
			}
		}
		cmd = ""
		fmt.Scanln(&cmd)
	}
}
