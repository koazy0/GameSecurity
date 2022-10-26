// fork.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <sys/types.h> 
#include <unistd.h>  
int main()
{
	pid_t= fork();
    std::cout << "Hello World!\n";
}
