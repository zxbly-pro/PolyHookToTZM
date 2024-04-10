;程序模板 微软官方解释https://learn.microsoft.com/zh-cn/cpp/assembler/masm/dot-386?view=msvc-150
;需要在项目属性->链接器->命令行添加 /SAFESEH:NO 不然会报错 模块对于 SAFESEH 映像是不安全的
;指明指令集386,表示要写386的程序(也就是32位)汇编程序
;在 VS2019 中，包括内联汇编代码或独立的 .asm 文件，都不需要显式地声明使用 SSE 指令集。你只需要直接写下 SSE 指令并在你的代码中使用 xmm 寄存器即可。
;.386
;程序工作模式,flat为Windows程序使用的模式(代码和数据使用同一个4GB段),c为API调用时右边的参数先入栈(内存设置为平坦模式,默认调用约定c)
.model flat,c
;堆栈大小
.stack 4096
;指明标识符大小写敏感
option casemap:none
;定义固定变量，程序运行过程中不再修改
.const
;对于所有要用到的函数，在程序的开始部分必须预先声明 函数名称 PROTO[调用规则]:[第一个参数类型][,:后续参数类型] 比如MessageBoxA PROTO :dword , :dword, :dword, :dword

;定义一个或多个名为“name”、类型为“type”的外部变量、标签或符号。
;EXTERNDEF [language-type] name:type [, [language-type] name:type ...]
;如果在模块中定义了名称，则它被视为 PUBLIC。 如果在模块中引用了名称 ，则它被视为 EXTERN。 如果未引用名称，则忽略它。 “type”可以是 ABS，它将“name”作为常量导入。 通常用于包含文件中
;;声明变量和函数
EXTERNDEF ogAdress:DWORD
EXTERNDEF HookFunc:PROTO
EXTERNDEF HookFuncCpu:PROTO

;定义代码段 类似于code segment
;变量定义
;[变量名] 助记符 表达式,[,表达式]
;表达式是 ? 则不进行初始化
;在这里声明变量
;32位没法把xmm寄存器传递进来,只能自己定义来替换
.data
	;4字节数字
	sss dword 999
	jinbi dword 999999999
	maxhpp dq  999999999.00
	;双浮点
	;maxhpp dq  999999999.00
;代码段，遇到end代码段结束
.code
;定义函数
HookFunc PROC
	    ;保存寄存器
		push eax;
		push ebx;
		push ecx;
		push edx;
		push esi;
		push edi;
		push ebp;
		push esp;
		;调用外部方法
		;call NewFunc;
		;还原寄存器
		pop esp;
		pop ebp;
		pop edi;
		pop esi;
		pop edx;
		pop ecx;
		pop ebx;
		pop eax;
		;夹带自己的私货
		mov eax, sss;
		;还原汇编代码(尽量对[edx]这种指定字节数dword ptr或者qword ptr)
		mov dword ptr[edx], eax;
		;跳转到ogAdress地址继续执行
		jmp ogAdress;
HookFunc ENDP
HookFuncCpu PROC
	    ;保存寄存器
		push eax;
		push ebx;
		push ecx;
		push edx;
		push esi;
		push edi;
		push ebp;
		push esp;
		;调用外部方法
		;call NewFunc;
		;还原寄存器
		pop esp;
		pop ebp;
		pop edi;
		pop esi;
		pop edx;
		pop ecx;
		pop ebx;
		pop eax;
		;夹带自己的私货
		mov eax, sss;
		;还原汇编代码(尽量对[edx]这种指定字节数dword ptr或者qword ptr)
		;movsd xmm0,maxhpp;
		;movsd qword ptr [esi+50h],xmm0;
		mov dword ptr[edx], eax;
		;跳转到ogAdress地址继续执行
		jmp ogAdress;
HookFuncCpu ENDP
HOOKjinbi PROC
	    ;保存寄存器
		push eax;
		push ebx;
		push ecx;
		push edx;
		push esi;
		push edi;
		push ebp;
		push esp;
		;调用外部方法
		;call NewFunc;
		;还原寄存器
		pop esp;
		pop ebp;
		pop edi;
		pop esi;
		pop edx;
		pop ecx;
		pop ebx;
		pop eax;
		;还原汇编代码(尽量对[edx]这种指定字节数dword ptr或者qword ptr)
		;mov dword ptr[esi+48h],jinbi;
		mov eax,jinbi;
		mov [esi+48h],eax;
		;跳转到ogAdress地址继续执行
		jmp ogAdress;
HOOKjinbi ENDP
HOOKmaxhp PROC
	    ;保存寄存器
		push eax;
		push ebx;
		push ecx;
		push edx;
		push esi;
		push edi;
		push ebp;
		push esp;
		;调用外部方法
		;call NewFunc;
		;还原寄存器
		pop esp;
		pop ebp;
		pop edi;
		pop esi;
		pop edx;
		pop ecx;
		pop ebx;
		pop eax;
		;还原汇编代码(尽量对[edx]这种指定字节数dword ptr或者qword ptr)
		movsd xmm0,maxhpp;
		movsd qword ptr [esi+50h],xmm0;
		;跳转到ogAdress地址继续执行
		jmp ogAdress;
HOOKmaxhp ENDP
END 
