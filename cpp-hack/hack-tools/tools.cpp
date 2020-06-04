#pragma once

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <regex>
#include <TlHelp32.h>
#include <Psapi.h>


std::string ReplaceString(std::string origenString, std::string replaceString, std::string newValue)
{
	int startIndex = origenString.find(replaceString);
	int endIndex = replaceString.size();
	return origenString.replace(startIndex, endIndex, newValue);
}

/*
	std::cout << HexStr2Hex("0A") << std::endl;
*/
uintptr_t HexStr2Hex(std::string hexStr)
{
	uintptr_t r;
	std::stringstream(hexStr) >> std::hex >> r;
	return r;
}

struct SplitListItem
{
	std::string key;
	std::string value;
};

/*
	std::vector<SplitListItem> r =	SplitString("asd-231-sfa:fa", (std::regex)"[-:]");
	std::cout << r[0].key << std::endl;
	std::cout << r[0].value << std::endl;
*/
std::vector<SplitListItem> SplitString(std::string origenString, std::regex pattern)
{
	std::smatch result;
	std::string::const_iterator iterStart = origenString.begin();
	std::string::const_iterator iterEnd = origenString.end();


	std::vector<std::string> splitList = {};
	std::vector<std::string> splitKeys = {};
	std::vector<SplitListItem> resultSplitList = {};

	while (regex_search(iterStart, iterEnd, result, pattern))
	{
		splitList.emplace_back(iterStart, result[0].first);
		splitKeys.push_back(result[0].str());
		iterStart = result[0].second;
	}
	splitList.emplace_back(iterStart, iterEnd);


	for (size_t i = 0; i < splitList.size(); i++)
	{
		resultSplitList.push_back(SplitListItem{ i > 0 ? splitKeys[i - 1] : "",  splitList[i] });
	}
	return resultSplitList;
}


// DLL
class GameExe
{
public:

	// pid
	DWORD PID = 0;

	// 进程句柄
	HANDLE hProcess = 0;

	// game.exe
	const wchar_t* moduleName = 0;

	// 系统为game.exe分配内存的基址
	uintptr_t moduleBaseAddress = 0;


	GameExe(const wchar_t* name)
	{
		this->moduleName = name;
		this->GetProcess();
	}
	~GameExe()
	{
		if (this->hProcess != 0)
		{
			CloseHandle(this->hProcess);
		}
	}

	// 返回模块基址
	// GetOffsetsAddress("game.exe")
	uintptr_t GetOffsetsAddress(std::string address, uintptr_t nextValue = 0)
	{
		std::string str = std::regex_replace(address, (std::regex)"\\s", "");
		std::smatch result;
		std::regex pattern(".*\\[([^\\[\\]]+)\\].*");
		std::regex_match(str, result, pattern);

		// 没匹配到，通常是简单的指针结构
		// 可能是;  GetOffsetsAddress("game.exe")
		// 可能是;  GetOffsetsAddress("game.exe+123")
		// 可能是;  GetOffsetsAddress("123")
		// 所有数数字当作16进制处理
		if (result.size() == 0)
		{
			if (str.size() == 0) {
				return nextValue;
			}

			std::vector<SplitListItem>  r = SplitString(str, (std::regex)"[+-]");

			uintptr_t a = HexStr2Hex(r[0].value);
			if (a == 0 && r[0].value != "0")
			{
				// 符号
				a = this->GetModuleBaseAddress();
			}
			uintptr_t b = HexStr2Hex(r[1].value);

			if (r[1].key == "+") a += b;
			if (r[1].key == "-") a -= b;
			return a;
		}



		std::vector<SplitListItem>  r = SplitString(result[1], (std::regex)"[+-]");
		uintptr_t data = 0;
		for (size_t i = 0; i < r.size(); i++)
		{
			uintptr_t v = HexStr2Hex(r[i].value);
			if (v == 0 && r[i].value != "0")
			{
				// 符号
				data += GetModuleBaseAddress();
			}
			else
			{
				if (r[i].key == "+") data += v;
				if (r[i].key == "-") data -= v;

				if (data != NULL)
					data = *(uintptr_t*)data;

				// ReadProcessMemory(hProcess, (LPCVOID)data, &data, 4, 0);
			}
		}

		std::stringstream hexData;
		hexData << std::hex << data;
		std::string newOrigenString = ReplaceString(str, "[" + result[1].str() + "]", hexData.str());
		return this->GetOffsetsAddress(newOrigenString, data);
	}


	/*
	  readIntger("game.exe+009E820C")
	  readIntger("[game.exe + 009E820C] + 338")
	*/
	uintptr_t readIntger(std::string address)
	{
		uintptr_t r = this->GetOffsetsAddress(address);
		if (r == 0) return 0;

		//外部hack
		//ReadProcessMemory(this->hProcess, (LPCVOID)r, &r, sizeof(uintptr_t), 0);
		//return r;

		return *(uintptr_t*)(r);
	}

	// writeIntger("[game.exe+ 009E820C] + 338", 20);
	uintptr_t writeIntger(std::string address, uintptr_t newInt)
	{
		uintptr_t r = this->GetOffsetsAddress(address);
		if (r == 0) return 0;

		// 外部hack
		// WriteProcessMemory(this->hProcess, (LPVOID)r, (LPCVOID)&newInt, sizeof(uintptr_t), 0);

		*(uintptr_t*)(r) = newInt;
	}


	/*
	扫描指定字节集,找到后返回Address
	uintptr_t address = ModuleScan(L"game2.exe", (BYTE*)"\xA3\x24\x37\x4B\x00", L"xxxxx");
	std::cout << std::hex << address << std::endl;
	*/
	uintptr_t ModuleScan(const wchar_t* moduleName, BYTE* bytes, const wchar_t* mask)
	{
		// https://docs.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
		MODULEINFO mInfo = this->GetModuleInfo(moduleName);

		// 起始位置
		uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;

		// 模块大小
		uintptr_t size = (uintptr_t)mInfo.SizeOfImage;

		int patternLen = wcslen(mask);
		wchar_t anyByte{ L'?' };

		for (size_t i = 0; i < size - patternLen; i++)
		{
			bool found = true;
			for (size_t j = 0; j < patternLen; j++)
			{
				found &= mask[j] == anyByte || bytes[j] == *(BYTE*)(base + i + j);
			}

			// return find address start
			if (found) return base + i;
		}

		return 0;
	}
	
	/*
	绕行/挂钩技术 和CE的AA脚本注入相似

	uintptr_t returnAddress;
	定义新的处理函数
	void __declspec(naked) myNewFunc() {
		//newmem:
		__asm {
			add esi, 0x64
			mov [edi + 0x00005578], esi
			jmp [returnAddress]
		}
	}

	uintptr_t injectAddress = 0x00433F86;
	int len = 6;
	returnAddress = injectAddress + len;
	ScriptInject((void*)injectAddress, myNewFunc, len);
	*/
	bool ScriptInject(void* injectAddress, void* scriptAddress, int len)
	{
		if (len < 5) return false;

		// 更改访问保护
		DWORD oldProc;
		VirtualProtect(injectAddress, len, PAGE_EXECUTE_READWRITE, &oldProc);

		// 先将旧的字节集设置为nop
		memset(injectAddress, 0x90, len);

		// 计算新的字节集
		// 跳转目标地址 - 当前指令地址 - 5 = 字节集
		uintptr_t relativeAddress = ((uintptr_t)scriptAddress - (uintptr_t)injectAddress - 5);

		// 设置jmp指令
		*(BYTE*)injectAddress = 0xE9;
		*(uintptr_t*)((uintptr_t)injectAddress + 1) = relativeAddress;

		// 修改后还原访问保护
		VirtualProtect(injectAddress, len, oldProc, &oldProc);

		return true;
	}

private:

	MODULEINFO GetModuleInfo(const wchar_t* mName)
	{
		MODULEINFO mInfo = { 0 };
		HMODULE hModule = GetModuleHandleW(mName);
		if (hModule == 0) return mInfo;

		// 在MODULEINFO结构中检索有关指定模块的信息
		GetModuleInformation(GetCurrentProcess(), hModule, &mInfo, sizeof(MODULEINFO));
		return mInfo;
	}

	HANDLE GetProcess()
	{
		if (this->hProcess != 0) return this->hProcess;
		this->GetPID();
		this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->PID);
		return this->hProcess;
	}

	// 获取进程名的pid
	DWORD GetPID()
	{
		if (this->PID != 0) return this->PID;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 pe;
			pe.dwSize = sizeof(pe);
			if (Process32First(hSnap, &pe))
			{
				do {
					if (!_wcsicmp(pe.szExeFile, this->moduleName)) {
						this->PID = pe.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnap, &pe));
			}
		}
		CloseHandle(hSnap);
		return this->PID;
	}

	// 获取模块基址
	uintptr_t GetModuleBaseAddress()
	{
		if (this->moduleBaseAddress != 0) return this->moduleBaseAddress;

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->PID);

		if (hSnap != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32 me;
			me.dwSize = sizeof(me);
			if (Module32First(hSnap, &me))
			{
				do {
					if (!_wcsicmp(me.szModule, this->moduleName)) {
						this->moduleBaseAddress = (uintptr_t)me.modBaseAddr;
						break;
					}
				} while (Module32Next(hSnap, &me));
			}
		}
		CloseHandle(hSnap);
		return this->moduleBaseAddress;
	}

};

