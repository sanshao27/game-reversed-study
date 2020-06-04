## 读写
```
	GameExe gameExe(L"game2.exe");
	
	std::cout << gameExe.readIntger("game2.exe+B3724") << std::endl;
	gameExe.writeIntger("game2.exe+B3724", );
	std::cout << gameExe.readIntger("game2.exe+B3724") << std::endl;

```

## script inject
```
uintptr_t returnAddress;

void __declspec(naked) myNewFunc() {
	//newmem:
	__asm {
		mov eax,0x64
		jmp [returnAddress]
	}
}

/*
game2.exe+1570 - E8 97FAFFFF           - call game2.exe+100C
>> game2.exe+1575 - A3 24374B00           - mov [game2.exe+B3724],eax
game2.exe+157A - 68 01030080           - push 80000301
*/
	uintptr_t address = gameExe.ModuleScan(gameExe.moduleName, (BYTE*)"\xA3\x24\x37\x4B\x00", L"xxxxx");
	
	// std::cout << std::hex << gameExe.GetOffsetsAddress("game2.exe+1575") << std::endl;

	uintptr_t injectAddress = gameExe.GetOffsetsAddress("game2.exe+1575");
	int len = 5;
	returnAddress = injectAddress + len;
	gameExe.ScriptInject((void*)address, myNewFunc, len);

```