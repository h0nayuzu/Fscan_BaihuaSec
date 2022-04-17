package common

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func Parse(Info *HostInfo) { //传递结构体指针。做了统一的接口。很干净。
	ParseScantype(Info) //配置扫描类型，应该通过不同字符串去调用加载器。
	ParseUser(Info)     //读取用户名
	ParsePass(Info)     //读取密码
	ParseInput(Info)    //写入信息
	//后面全是方法的实现过程
}

func ParseUser(Info *HostInfo) { //读用户列表
	if Info.Username == "" && Userfile == "" {
		return
	}

	if Info.Username != "" {
		Info.Usernames = strings.Split(Info.Username, ",")
	}

	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Info.Usernames = append(Info.Usernames, user)
				}
			}
		}
	}

	Info.Usernames = RemoveDuplicate(Info.Usernames)
	for name := range Userdict {
		Userdict[name] = Info.Usernames
	}
}

func ParsePass(Info *HostInfo) { // 读密码列表
	if Info.Password != "" {
		passs := strings.Split(Info.Password, ",")
		for _, pass := range passs {
			if pass != "" {
				Info.Passwords = append(Info.Passwords, pass)
			}
		}
		Passwords = Info.Passwords
	}
	if Passfile != "" {
		passs, err := Readfile(Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					Info.Passwords = append(Info.Passwords, pass)
				}
			}
			Passwords = Info.Passwords
		}
	}
	if UrlFile != "" {
		urls, err := Readfile(UrlFile)
		if err == nil {
			TmpUrls := make(map[string]struct{})
			for _, url := range urls {
				if _, ok := TmpUrls[url]; !ok {
					TmpUrls[url] = struct{}{}
					if url != "" {
						Urls = append(Urls, url)
					}
				}
			}
		}
	}
}

func Readfile(filename string) ([]string, error) { // 读扫描目标
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, scanner.Text())
		}
	}
	return content, nil
}

func ParseInput(Info *HostInfo) { // 判断目标是否存在 然后写入信息包括端口
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(0)
	}

	if TmpOutputfile != "" {
		if !strings.Contains(Outputfile, "/") && !strings.Contains(Outputfile, `\`) {
			Outputfile = getpath() + TmpOutputfile
		} else {
			Outputfile = TmpOutputfile
		}
	}
	if TmpSave == true {
		IsSave = false
	}
	if Info.Ports == DefaultPorts {
		Info.Ports += "," + Webport
	}

	if PortAdd != "" {
		if strings.HasSuffix(Info.Ports, ",") {
			Info.Ports += PortAdd
		} else {
			Info.Ports += "," + PortAdd
		}
	}

	if UserAdd != "" {
		user := strings.Split(UserAdd, ",")
		for a, _ := range Userdict {
			Userdict[a] = append(Userdict[a], user...)
			Userdict[a] = RemoveDuplicate(Userdict[a])
		}
	}

	if PassAdd != "" {
		pass := strings.Split(PassAdd, ",")
		Passwords = append(Passwords, pass...)
		Passwords = RemoveDuplicate(Passwords)
	}
}

func ParseScantype(Info *HostInfo) { // 设置扫描类型
	_, ok := PORTList[Info.Scantype]
	if !ok {
		showmode()
	}
	if Info.Scantype != "all" {
		if Info.Ports == DefaultPorts {
			switch Info.Scantype {
			case "rdp":
				Info.Ports = "3389"
			case "wmi":
				Info.Ports = "135"
			case "web":
				Info.Ports = Webport
			case "webonly":
				Info.Ports = Webport
			case "ms17010":
				Info.Ports = "445"
			case "cve20200796":
				Info.Ports = "445"
			case "smb2":
				Info.Ports = "445"
			case "portscan":
				Info.Ports = DefaultPorts + "," + Webport
			case "main":
				Info.Ports = DefaultPorts
			default:
				port, _ := PORTList[Info.Scantype]
				Info.Ports = strconv.Itoa(port)
			}
			fmt.Println("-m ", Info.Scantype, " start scan the port:", Info.Ports)
		}
	}
}

func CheckErr(text string, err error, flag bool) { // 异常输出
	if err != nil {
		fmt.Println("Parse", text, "error: ", err.Error())
		if flag {
			if err != ParseIPErr {
				fmt.Println(ParseIPErr)
			}
			os.Exit(0)
		}
	}
}

func getpath() string { // 获取路径
	file, _ := exec.LookPath(os.Args[0])
	path1, _ := filepath.Abs(file)
	filename := filepath.Dir(path1)
	var path string
	if strings.Contains(filename, "/") {
		tmp := strings.Split(filename, `/`)
		tmp[len(tmp)-1] = ``
		path = strings.Join(tmp, `/`)
	} else if strings.Contains(filename, `\`) {
		tmp := strings.Split(filename, `\`)
		tmp[len(tmp)-1] = ``
		path = strings.Join(tmp, `\`)
	}
	return path
}

func showmode() { // 模式选择错误
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for name := range PORTList {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(0)
}
