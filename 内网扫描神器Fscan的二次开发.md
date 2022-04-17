# 内网扫描神器Fscan的二次开发

------

### INFO

version：`1.7.0.0 Red_Team` 

Author：`Team_白桦 Hanayuzu`

### 修改内容：

- `1.7.0.0 Red_Team` 
  1. 添加了来自`xray`社区的17个POC，大部分未做测试，可能误报漏报
  2. 修改了默认扫描的web端口，添加了一些实际渗透中遇到过的端口
  3. 增加了一些默认弱口令账密
  4. Banner处添加`Team_白桦`
  5. 部分代码添加的注释



- 修改后的源码和编译文件：https://wwu.lanzout.com/iOHr80195w4h

------

参考：

https://blog.csdn.net/qq_35476650/article/details/119536978



别的不说，go是真的啥也不会，写一点更一点

## 0、FSCAN架构模式

![fscan架构](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/265f8ed6481f437a8422aaa2f67e7f4c.png)





### 一、导入项目

导入原版项目

```
git clone https://github.com/shadow1ng/fscan.git
```



打开Goland，打开项目设置搜索关键字`代理`，英文`proxy`，配置一下，不然没法构建

![image-20220307183805024](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220307183805024.png)



#### 修改ceye.io

打开`\fscan-main\WebScan\lib\check.go`20行，把默认的ceye.io改成自己的

![image-20220307184042601](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220307184042601.png)

修改部分配置文件：

在这个路径的config文件中修改默认扫描的端口，添加字典

`\fscan-main\common\config.go`

![image-20220310115814527](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220310115814527.png)

OK，修改的地方就这么点。

然后就是POC部分；fscan的poc是和xray v1 poc通用的。所以，只要花亿点点时间，去xray的pull里找poc就好了。

https://github.com/chaitin/xray/pulls?q=is%3Apr+is%3Aclosed

![image-20220307194858168](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220307194858168.png)

然后将保存的poc修改一下。复制到fscan的poc里就ok了

![image-20220307195027071](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220307195027071.png)

这次增加了17个poc，大部分没验证，可能误报漏报。

![image-20220310140523092](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220310140523092.png)

全部弄好后，编译

```
go build .\main.go
```

![image-20220307195421027](https://hanayuzu-images.oss-cn-hangzhou.aliyuncs.com/images/image-20220307195421027.png)