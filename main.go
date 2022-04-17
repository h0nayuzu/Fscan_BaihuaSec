package main

import ( //导包
	"fmt"
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
	"time"
)

func main() { //主函数
	start := time.Now()
	var Info common.HostInfo // 这是结构体
	common.Flag(&Info)       // 输出Banner
	common.Parse(&Info)      // 格式化IP
	Plugins.Scan(Info)       // 传入结构体，然后配置进行扫描
	t := time.Now().Sub(start)
	fmt.Printf("[*] 扫描结束,耗时: %s", t)
}
