;注释:
;申明需要引入或者导出的变量或者函数,dq表示qdword=64位
extern ogAdress:dq;
;far为函数标记
extern NewFunc:far;
extern NewFuncCpu:far;

;代码区开始
.code
;方法开始
HookFunc PROC
;保存寄存器
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
;保存完寄存器后可以随意调外部方法(仅hook函数时可以调用,hook代码段会导致未知异常)
;call NewFunc;
;还原寄存器
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
;由于在NewFunc中将og_fun偏移到ogAdress,需要还原og_fun到ogAdress之间的字节避免失衡
;函数头mov qword ptr [rsp+10H],rdx
;夹带自己的私货
mov eax,666
;还原汇编代码(尽量对[rcx]这种指定字节数dword ptr或者qword ptr)
mov dword ptr [rcx],eax
;跳转到ogAdress地址继续执行
jmp ogAdress;
;函数结束
HookFunc ENDP
;函数开始
HookFuncCpu PROC
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push rsp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
pushf
;保存完寄存器后可以随意调外部方法(仅hook函数时可以调用,hook代码段会导致未知异常)
;call NewFuncCpu;
;还原寄存器
popf
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rsp
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
;由于在NewFuncCpu中将og_fun偏移到ogAdress,需要还原og_fun到ogAdress之间的字节避免失衡
;函数头mov qword ptr [rsp+10H],rdx
;夹带自己的私货
mov eax,666
;还原汇编代码(尽量对[rcx]这种指定字节数dword ptr或者qword ptr)
mov dword ptr [rcx],eax
;跳转到ogAdress地址继续执行
jmp ogAdress;
;函数结束
HookFuncCpu ENDP
;方法区结束
end