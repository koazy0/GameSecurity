## koazy0/GameSecurity

### 前言

​		当前code为某企校联合举办的课程，这里仅针对课上的所讲的方法写出demo~实际上作业也能用，clone到本地改一下就行了

​		当前目录结构说明如下：

- test：编译好的文件

### Chapter 1 初识Hook

#### 1.3 几种常见的hook

##### 1.3.1 CreateRemoteThread



##### 1.3.2 ApcHook



##### 1.3.3 SetWindowsHookEx

​	 	打开1.4\test1\test1.sln工程文件。

​		检查dll是否正确:stud_PE查看导出函数，如下所示:

![image-20221025233100560](pic\image-20221025233100560.png)

##### 1.3.4 虚函数表hook

​		这个我还没写，等到后面补上吧~

##### 1.3.5 IAT_hook

​		参考书籍：《逆向工程核心原理》

​		以win7下的calc.exe为例(该程序为32位程序)，进行IAT hook。

**基础知识:PE文件结构**

​		`IMAGE_IMPORT_DESCRIPTOR`的结构如下所示：

~~~c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;							//RVA of Dll name
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
}
~~~

以user32为例举例，

![image-20221027160543921](pic\image-20221027160543921.png)

第一项为指向函数名表的rva，找到对应RVA，可得到如下截图，即

![image-20221027160910743](pic\image-20221027160910743.png)

查看4AD6C的内容，发现是Word(fun)+Name(proc)的形式(这里截图省略)；

对于最后一项FIRST_CHUNK_RVA，就是指向IAT表的地址![image-20221027161353214](pic\image-20221027161353214.png)

**hook步骤**

1.  `HANDLE Hmod=GetModuleHandle(NULL);	//获取当前基址`

2. 	找寻IDT所在地址，得到加载的dll的信息
~~~
   DWORD pAddr=HMOD+Hmod[0x3C];	//NT header
   pAddr=pAddr+0x80;				//VA of Import table in Data Directories
   pAddr+=(DWORD)*pAddr;			//VA of Import Directory Table
~~~

3.  遍历IDT，通过对比Name从而找到目标Dll

4.  同时记录ImportNameTable和对应的IAT基址

5.  通过对比ImportName的name(fun)来确定偏移地址，同时定位IAT对应函数的offset

   > - 可以通过地址自增实现
   > - name(fun)是 const char[]，与程序编码选择(ANSI/Unicode)无关



**具体代码**

IAT_Hook.cpp 是自我Hook，目标函数为SetWindowTextW;

工程中的是通过注入dll的方式，实现对win7下32位calc.exe进行IAT hook。





**注意事项**

​		1.当使用PEView查看时，应使用RVA而不是file offset查看偏移，否则得到的结果不对。File offset是文件中的offset,RVA是加载到进程空间后的offset，这两点不一样，故这里指出。

![image-20221027155109522](pic\image-20221027155109522.png)

​		2.另外，注入dll的时候可以用Messagebox来验证是否注入成功；如果没注入成功，没有实行msgbox的话，可以通过IDA查看，如果看到ida是有`DisableThreadLibraryCalls()`则说明入口函数有问题。



#### 1.4 内存检测与拷贝

​		

### Chapter 2 

#### 2.1 游戏进程的模块信息获取

![image-20221026152045639](pic\image-20221026152045639.png)

#### 2.2 注入技术的实现原理

#### 2.3 Hook技术的实现原理

#### 2.4 篡改游戏内容的实现原理

### 课后作业
