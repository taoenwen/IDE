#include <iostream>
#include <tchar.h>
#include <io.h>

#define MAX_PATH 260 * sizeof(TCHAR)

bool PrintStatement(const PTCHAR pszAppName)
{
    if (NULL == pszAppName) return false;

    _tprintf(_T("%s FinalBurn Neo %s\n"), _T("本控制台程序的部分代码引用自"), _T("项目的代码"));
    _tprintf(_T("%s FBNeo/src/burner/win32/ips_manager.cpp %s\n"), _T("其中含有对"), _T("部分代码的引用"));
    _tprintf(_T("%s https://github.com/finalburnneo/FBNeo\n\n"), _T("详情请访问:"));

    return true;
}

bool PrintHelp(const PTCHAR pszAppName)
{
    if (NULL == pszAppName) return false;

    _tprintf(_T("%s [option] <path[1]> <path[2]> <path[n]> ...\n\n"), pszAppName);
    _tprintf(_T("   [option]\n"));
    _tprintf(_T("           %s\n"), _T("无参数，导出 IPS 的解析文本，需指定 IPS 文件路径"));
    _tprintf(_T("       -a  %s\n"), _T("导出程序同目录下全部 IPS 的解析文本，并忽略后续参数"));
    _tprintf(_T("       /a  %s -a\n"), _T("等价于"));
    _tprintf(_T("       -d  %s\n"), _T("导出指定目录下全部 IPS 的解析文本"));
    _tprintf(_T("       /d  %s -d\n\n"), _T("等价于"));
    _tprintf(_T("   <path[1...n]>\n"));
    _tprintf(_T("       <path>\n"));
    _tprintf(_T("           %s  xx.ips\n"), _T("位于程序同目录，无空格的 IPS 的相对路径"));
    _tprintf(_T("           %s  \"x x.ips\"\n"), _T("位于程序同目录，有空格的 IPS 的相对路径"));
    _tprintf(_T("           %s  x:\\xx.ips\n"), _T("带驱动器盘符，无空格的 IPS 的绝对路径"));
    _tprintf(_T("           %s  \"x:\\x x.ips\"\n\n"), _T("带驱动器盘符，有空格的 IPS 的绝对路径"));
    _tprintf(_T("           %s  x:\\xx\n"), _T("带驱动器盘符，无空格的绝对路径目录"));
    _tprintf(_T("           %s  \"x:\\x x\"\n\n"), _T("带驱动器盘符，有空格的绝对路径目录"));
    _tprintf(_T("       [1...n]\n"));
    _tprintf(_T("           %s\n\n"), _T("允许输入多个 IPS 文件或目录"));
    _tprintf(_T("   [%s]\n"), _T("示例"));
    _tprintf(_T("       %s xx.ips\n"), pszAppName);
    _tprintf(_T("       %s xx.ips \"x x.ips\" x:\\xx.ips \"x:\\x x.ips\"\n"), pszAppName);
    _tprintf(_T("       %s -a\n"), pszAppName);
    _tprintf(_T("       %s -d \"x:\\x x\"\n\n"), pszAppName);

    _tsystem(_T("pause"));

    return true;
}

int AnalysisIPSFile(const PTCHAR pszIPS)
{
    if (NULL == pszIPS) {
        _tprintf(_T("%s\n"), _T("程序异常，无法获取文件"));
        return -1;
    }

    FILE* f = _tfopen(pszIPS, _T("rb"));

    // 目标文件不存在
    if (NULL == f) {
        _tprintf(_T("%s %s\n"), _T("找不到指定文件"), pszIPS);
        return 1;
    }

    char buf[6] = { 0 };
    fread(buf, 1, 5, f);

    // 不是 IPS 文件
    if (strcmp(buf, "PATCH")) {
        fclose(f);
        _tprintf(_T("%s %s\n"), pszIPS, _T("不是有效的 IPS 文件"));
        return 2;
    }

    TCHAR p[MAX_PATH] = { 0 };
    _tcsncpy(p, pszIPS, _tcslen(pszIPS) - _tcslen(_T(".ips")));
    _tcscat(p, _T(".txt"));

    FILE* t = _tfopen(p, _T("w"));

    // 文本文件无法创建
    if (NULL == t) {
        fclose(f);
        _tprintf(_T("%s %s\n"), _T("遇到问题，无法创建"), p);
        return 4;
    }

    unsigned int ch = 0, mem8 = 0;
    int Offset = 0, Size = 0;
    bool bRLE = false;
    char v[17] = {};

#define BYTE3_TO_UINT(bp) \
     (((unsigned int)(bp)[0] << 16) & 0x00FF0000) | \
     (((unsigned int)(bp)[1] << 8) & 0x0000FF00) | \
     ((unsigned int)(bp)[2] & 0x000000FF)

#define BYTE2_TO_UINT(bp) \
     (((unsigned int)(bp)[0] << 8) & 0xFF00) | \
     ((unsigned int) (bp)[1] & 0x00FF)

    while (!feof(f)) {
        // 读取补丁在 ROM 的每个地址的偏移量
        fread(buf, 1, 3, f);
        buf[3] = 0;

        // 到达 IPS 文件的末尾则停止
        if (0 == strcmp(buf, "EOF")) break;

        Offset = BYTE3_TO_UINT(buf);

        //读取补丁每段连续地址的长度
        fread(buf, 1, 2, f);                                
        Size = BYTE2_TO_UINT(buf);

        bRLE = (Size == 0);
        if (bRLE) {
            fread(buf, 1, 2, f);
            Size = BYTE2_TO_UINT(buf);
            ch = fgetc(f);
        }

        while (Size--) {
            Offset++;

            // 修改值
            mem8 = bRLE ? ch : fgetc(f);

            // [ROM 地址] [修改值]
            // 示例:
            // 0x006c18, 0x10,
            // 0x00914d, 0x05,
            // ...
            memset(v, 0, sizeof(v));
            sprintf(v, "0x%06x, 0x%02x,\n", Offset - 1, mem8);
            fwrite(v, sizeof(v) - 1, 1, t);
        }
    }
    fclose(t);
    _tprintf(_T("%s %s\n"), pszIPS, _T("解析完成"));
    fclose(f);

    return 0;
}

void ListFiles(const PTCHAR pszDir)
{
    if (NULL == pszDir) {
        _tprintf(_T("%s\n"), _T("程序异常，无法获取目录"));
        return;
    }

    TCHAR szNewDir[MAX_PATH] = { 0 };
    _tcscpy(szNewDir, pszDir);

    // 在目录后面加上"\\*.*"进行第一次搜索
    _tcscat(szNewDir, _T("\\*.*"));

    intptr_t handle = 0;
    _tfinddata_t findData = { 0 };

    // 检查是否成功
    if (-1 == (handle = _tfindfirst(szNewDir, &findData))) {
        _tprintf(_T("%s %s\n"), pszDir, _T("找不到目录或目录中没有文件"));
        return;
    }

    do {
        if (findData.attrib & _A_SUBDIR) {
            // 使用 _tfindfirst() _tfindnext() 进行搜索时，可能会得到"."和".."两个文件夹名。这两个值可以忽略。
            if (_tcscmp(findData.name, _T(".")) == 0 || _tcscmp(findData.name, _T("..")) == 0) continue;

            // 在目录后面加上"\\"和搜索到的目录名进行下一次搜索
            _stprintf(szNewDir, _T("%s\\%s"), pszDir, findData.name);
            _tprintf(_T("%s %s\n"), _T("发现目录"), szNewDir);

            // 递归查找
            ListFiles(szNewDir);
        } else {
            TCHAR szNewFile[MAX_PATH] = { 0 };

            // 文件添加绝对路径
            _stprintf(szNewFile, _T("%s\\%s"), pszDir, findData.name);
            _tprintf(_T("%s %s\n"), _T("找到文件"), szNewFile);
            AnalysisIPSFile(szNewFile);
        }
    } while (_tfindnext(handle, &findData) == 0);

    _findclose(handle);
}

int _tmain(int argc, TCHAR* argv[])
{
    _tsetlocale(LC_ALL, _T("CHS"));

    TCHAR* pszAppName = _tcsrchr(argv[0], _T('\\')) + 1, szAppPath[MAX_PATH] = { 0 };
    PrintStatement(pszAppName);

    // IPS 文件模式开关
    bool bFileMode = false;

    switch (argc)
    {
    case 1:
        PrintHelp(pszAppName);
        break;

    default:
        int i = 1, nIndex = 0;
        while (nIndex = i, i++ < argc) {
            // 检查 argv[1] [option]
            if (2 == i) {
                // [option] 参数不存在，IPS 文件模式
                if (0 != _tcsicmp(argv[nIndex], _T("-a")) && 0 != _tcsicmp(argv[nIndex], _T("/a")) && 0 != _tcsicmp(argv[nIndex], _T("-d")) && 0 != _tcsicmp(argv[nIndex], _T("/d")))
                    // IPS 文件模式开启
                    bFileMode = true;

                // 参数 -a | /a，不分大小写，程序同目录搜索，忽略后续参数
                if (0 == _tcsicmp(argv[nIndex], _T("-a")) || 0 == _tcsicmp(argv[nIndex], _T("/a"))) {
                    ListFiles(_tgetcwd(szAppPath, MAX_PATH));
                    break;
                }
            }

            if (bFileMode) {
                AnalysisIPSFile(argv[nIndex]);
                continue;
            }

            // 参数 -d | /d，不分大小写，搜索指定目录
            if (2 < i && !bFileMode) ListFiles(argv[nIndex]);
        }
        break;
    }
    return 0;
}
