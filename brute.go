package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

func getAllCiphers() []string {
	out, err := exec.Command("openssl", "enc", "-ciphers").Output()
	if err != nil {
		panic(err)
	}
	regex := regexp.MustCompile(`-([\w|-]+)`)
	allCiphers := regex.FindAllStringSubmatch(string(out), -1)
	ciphers := make([]string, len(allCiphers))
	for index := range allCiphers {
		ciphers[index] = allCiphers[index][1]
	}
	return ciphers

}

func argParse() (string, string, []string) {
	wordlistPath := flag.String("wordlist", "/usr/share/wordlists/rockyou.txt", "Wordlist to use.")
	encFile := flag.String("file", "", "File to decrypt. (Required)")
	ciphers := flag.String("ciphers", "All openssl ciphers", "Specify cipher types comma separated.")
	printCipher := flag.Bool("print", false, "Set to print all available ciphers and exit.")
	flag.Parse()

	if *printCipher == true {
		printAllCiphers()
		os.Exit(0)
	}

	if *encFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ciphersSlice := getAllCiphers()
	if *ciphers != "All openssl ciphers" {
		ciphersSlice = strings.Split(*ciphers, ",")
	}
	return *wordlistPath, *encFile, ciphersSlice
}

func printAllCiphers() {
	ciphersSlice := getAllCiphers()
	for index := range ciphersSlice {
		fmt.Printf("[ %s ] ", ciphersSlice[index])
		if (index+1)%4 == 0 {
			fmt.Print("\n")
		}
	}
	fmt.Println()
}

func crack(cipher string, encFile string, wordlistPath string, wg *sync.WaitGroup, found chan<- string, stop <-chan bool) {
	defer wg.Done()
	fmt.Printf("Trying cipher %s\n", cipher)
	cmdFormat := "openssl enc -d -a -%s -in %s -out %s -pass pass:%s"
	fileName := "result-" + cipher
	// read big file
	inFile, err := os.Open(wordlistPath)
	defer inFile.Close()
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	// loop line by line
	for scanner.Scan() {
		select {
		case <-stop:
			fmt.Printf("Stopping worker: %s\n", cipher)
			return
		default:
			word := scanner.Text()
			cmd := fmt.Sprintf(cmdFormat, cipher, encFile, fileName, word)
			command := strings.Split(cmd, " ")
			_, err := exec.Command(command[0], command[1:]...).Output()
			// if no errors => found correct pass
			if err == nil && isASCIITextFile(fileName) {
				fmt.Println(strings.Repeat("-", 50))
				fmt.Printf("Found password [ %s ] using [ %s ] algorithm!!\n", word, cipher)
				fmt.Println(strings.Repeat("-", 50))
				data, _ := ioutil.ReadFile(fileName)
				fmt.Println(string(data))
				fmt.Println(strings.Repeat("-", 50))
				found <- fileName
				return
			}
		}
	}
}

func watcher(wg *sync.WaitGroup, watch chan<- bool) {
	defer close(watch)
	wg.Wait()
}

func removeJunkFiles(goodFile string) {
	files, err := ioutil.ReadDir("./")
	if err != nil {
		panic(err)
	}

	for _, f := range files {
		fileName := f.Name()
		if strings.HasPrefix(fileName, "result-") && fileName != goodFile {
			err := os.Remove(fileName)
			if err != nil {
				panic(err)
			}
		}
	}
}

func isASCIITextFile(filePath string) bool {

	file, err := os.Open(filePath)
	defer file.Close()
	if err != nil {
		panic(err)
	}

	buffer := make([]byte, 256)
	_, err = file.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	text := string(buffer)
	for char := 0; char < 256; char++ {
		if text[char] >= 128 {
			return false
		}
	}
	return true
}

func main() {
	wordlist, encryptedFile, ciphers := argParse()
	alreadyFound := false
	resultFile := ""
	found := make(chan string)
	stop := make(chan bool)
	watch := make(chan bool)

	var wg sync.WaitGroup
	// loop throught the ciphers and start a routine
	for _, cipher := range ciphers {
		wg.Add(1)
		go crack(cipher, encryptedFile, wordlist, &wg, found, stop)
	}
	go watcher(&wg, watch)
Waiting:
	for {
		select {
		case <-watch:
			fmt.Println("All Workers Closed")
			break Waiting
		case resultFile = <-found:
			if !alreadyFound {
				alreadyFound = true
				close(stop)
			}
		}
	}
	if alreadyFound {
		fmt.Printf("CRACKED!! Results in file [ %s ]", resultFile)
	}

	fmt.Println("Program Exit")
	removeJunkFiles(resultFile)
}
