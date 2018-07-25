# go-openssl-bruteforce

A fast multi-threaded tool to bruteforce openssl ciphers with a wordlist against an encrypted file.

## Usage
```
./openssl-brute -file <encrypted file>
```

### All options
```
$ ./openssl-brute 
  -ciphers string
    	Specify cipher types comma separated. (default "All openssl ciphers")
  -file string
    	File to decrypt. (Required)
  -print
    	Set to print all available ciphers and exit.
  -wordlist string
    	Wordlist to use. (default "/usr/share/wordlists/rockyou.txt")
```

**Compiled versions on the release tab.** [here](https://github.com/deltaclock/go-openssl-bruteforce/releases)

## Build from source
```
git clone https://github.com/deltaclock/go-openssl-bruteforce.git
cd go-openssl-bruteforce/
go build -o openssl-brute
```
