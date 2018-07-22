package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
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
	flag.Parse()

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

func crack(cipher string, encFile string, wordlistPath string) {
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
		word := scanner.Text()
		cmd := fmt.Sprintf(cmdFormat, cipher, encFile, fileName, word)
		command := strings.Split(cmd, " ")
		_, err := exec.Command(command[0], command[1:]...).Output()
		// if no errors => found correct pass
		if err == nil {
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("Found password [ %s ] using [ %s ] algorithm!!\n", word, cipher)
			fmt.Println(strings.Repeat("-", 50))
			data, _ := ioutil.ReadFile(fileName)
			fmt.Println(string(data))
			fmt.Println(strings.Repeat("-", 50))
			os.Exit(0)
		}
	}
}

func main() {
	wordlist, encryptedFile, ciphers := argParse()
	for _, cipher := range ciphers {
		crack(cipher, encryptedFile, wordlist)
	}
}
