#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>
#include <sys/stat.h>

#if defined(WIN32)
	#include <io.h>
	#include <windows.h>
	#include <crtdbg.h>
	
	#pragma warning(disable: 4996)
#else
	#define __STDC_FORMAT_MACROS
	#include <inttypes.h>
	#include <unistd.h>
	#include "portable.h"
#endif

#define LENGTH_PACKET		188
#define MAX_PID				8192
#define LENGTH_CRC_DATA		16
#define false				0
#define true				1

#define TSS_SUCCESS			0
#define TSS_ERROR			-1

/**************************************************************************/

/**
 * 引数用構造体
 */
typedef struct {
	char* src;				// 入力ファイル
	char* dst;				// 出力ファイル
	char* sid;				// 出力対象チャンネル番号
	int useFifo;			// FIFO 使用フラグ
} PARAM;

/**************************************************************************/

void show_usage();
int AnalyzeParam(int argc, char** argv, PARAM* param);

int execute(PARAM* param);

int ReadTs(int* sfd, unsigned char** pat, unsigned char* pids, char* sid);
int WriteTs(int* sfd, int* dfd, unsigned char** pat, unsigned char* pids);

int AnalyzePat(unsigned char* buf, unsigned char** pat, unsigned char* pids, char* sid, int* pmt_pid);
int RecreatePat(unsigned char* buf, unsigned char** pat, unsigned char* pids, int pos);
int AnalyzePmt(unsigned char* buf, unsigned char* pids);

char* ToLower(char* s);
int GetCrc32(unsigned char* data, int len);
int GetPid(unsigned char* data);

/**************************************************************************/

/**
 *
 */
int main(
	int argc,							// [in]		引数の個数
	char** argv)						// [in]		引数
{
	PARAM param;

	int result;							// 処理結果

	// パラメータ解析
	result = AnalyzeParam(argc, argv, &param);
	if (TSS_SUCCESS != result)
	{
		return result;
	}

	// 処理実行
	result = execute(&param);

	return result;
}

/**
 * 使用方法メッセージ出力
 */
void show_usage()
{
	fprintf(stderr, "tssplitter_lite - tssplitter_lite program Ver. 0.0.0.1\n");
	fprintf(stderr, "usage: tssplitter_lite src.ts dst.ts [options]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -f : use fifo\n");
	fprintf(stderr, "\n");
}

/**
 * パラメータ解析
 */
int AnalyzeParam(
	int argc,							// [in]		引数の個数
	char** argv,						// [in]		引数
	PARAM* param)						// [out]	引数情報データ
{
	// 引数チェック
	if ((4 != argc) && (5 != argc))
	{
		show_usage();
		return TSS_ERROR;
	}

	param->src		= argv[1];
	param->dst		= argv[2];
	param->sid		= argv[3];

	// FIFO を利用する場合
	if (5 == argc)
	{
		if (0 == strcmp(ToLower(argv[4]), "-f"))
		{
			param->useFifo = true;
		}
	}

	return TSS_SUCCESS;
}

/**
 * 実処理
 */
int execute(
	PARAM* param)						// [in]		引数情報データ
{
	int result;

	int sfd					= -1;		// ファイル記述子（読み込み用）
	int dfd					= -1;		// ファイル記述子（書き込み用）

	unsigned char pids[MAX_PID];
	unsigned char* pat = NULL;

	// 初期化
	memset(pids, 0, MAX_PID);

	// 読み込みファイルオープン
	sfd = _open(param->src, _O_BINARY|_O_RDONLY|_O_SEQUENTIAL);
	if (sfd < 0)
	{
		goto LAST;
	}

	// 書き込みファイルオープン
	dfd = _open(param->dst, _O_WRONLY|_O_BINARY|_O_CREAT|_O_TRUNC, _S_IREAD|_S_IWRITE);
	if (dfd < 0)
	{
		goto LAST;
	}

	// ファイル入力
	result = ReadTs(&sfd, &pat, pids, param->sid);
	if (TSS_SUCCESS != result)
	{
		goto LAST;
	}

	if (false == param->useFifo)
	{
		_lseeki64(sfd, 0, SEEK_SET);
	}

	// ファイル出力
	result = WriteTs(&sfd, &dfd, &pat, pids);
	if (TSS_SUCCESS != result)
	{
		goto LAST;
	}

LAST:
	// 開放処理
	if (NULL != pat)
	{
		free(pat);
	}
	if (0 <= dfd)
	{
		_close(dfd);
	}
	if (0 <= sfd)
	{
		_close(sfd);
	}

	return TSS_SUCCESS;
}

/**
 * TS ファイル読み込み処理
 *
 * TS ファイルを読み込み、対象のチャンネル番号のみの PAT の再構築と出力対象 PID の抽出を行う
 */
int ReadTs(
	int* sfd,							// [in]		ファイル記述子（読み込み用）
	unsigned char** pat,				// [out]	PAT 情報（再構築後）
	unsigned char* pids,				// [out]	出力対象 PID 情報
	char* sid)							// [in]		出力対象サービス ID
{
	unsigned int pmt_pid = 0xFFFF;
	
	int length;
	unsigned char buf[LENGTH_PACKET];

	while ((length = _read(*sfd, buf, sizeof(buf))) > 0)
	{
		int pid;
		pid = GetPid(&buf[1]);
		// PAT
		if (0x0000 == pid)
		{
			int result;
			result = AnalyzePat(buf, pat, pids, sid, &pmt_pid);
			if (TSS_SUCCESS != result)
			{
				return result;
			}
		}

		// PMT
		if (pmt_pid == pid)
		{
			AnalyzePmt(buf, pids);
			break;
		}
	}

	return TSS_SUCCESS;
}

/**
 * TS ファイル書き込み処理
 */
int WriteTs(
	int* sfd,							// [in]		ファイル記述子（読み込み用）
	int* dfd,							// [in]		ファイル記述子（書き込み用）
	unsigned char** pat,				// [out]	PAT 情報（再構築後）
	unsigned char* pids)				// [out]	出力対象 PID 情報
{
	unsigned char count = 0xFF;
	int length;
	unsigned char buf[LENGTH_PACKET];

	while ((length = _read(*sfd, buf, sizeof(buf))) > 0)
	{
		int pid;
		pid = GetPid(&buf[1]);

		// PAT
		if (0x0000 == pid)
		{
			// 巡回カウンタカウントアップ
			if (0xFF == count)
			{
				count = (*pat)[3];
			} else
			{
				count++;
				if (0 == count % 0x10)
				{
					count = count - 0x10;
				}
			}
			(*pat)[3] = count;

			_write(*dfd, *pat, LENGTH_PACKET);
		}

		// その他 PID
		else
		{
			if (1 == pids[pid])
			{
				_write(*dfd, buf, LENGTH_PACKET);
			}
		}
	}

	return TSS_SUCCESS;
}

/**
 * PAT 解析処理
 *
 * PAT を解析し、出力対象チャンネルが含まれているかチェックを行い、PAT を再構築する
 */
int AnalyzePat(
	unsigned char* buf,					// [in]		読み込んだバッファ
	unsigned char** pat,				// [out]	PAT 情報（再構築後）
	unsigned char* pids,				// [out]	出力対象 PID 情報
	char* sid,							// [in]		出力対象サービス ID
	int* pmt_pid)						// [out]	サービス ID に対応する PMT の PID
{
	int pos			= 0;

	// 対象チャンネル判定
	{
		int i;
		for (i = 17; i < LENGTH_PACKET - 4; i = i + 4)
		{
			int service_id;

			// データの終了判定
			// 最後の CRC の判定もしないといけないなあ
			if ((buf[i + 2] == 0xFF) && (buf[i +3] == 0xFF))
			{
				return TSS_ERROR;
			}

			service_id = (buf[i] << 8) + buf[i + 1];
			if (service_id == atoi(sid))
			{
				*pmt_pid = GetPid(&buf[i + 2]);
				pos = i;
				break;
			}
		}
	}

	pids[*pmt_pid] = 1;

	// PAT 再構築
	if (NULL == *pat)
	{
		RecreatePat(buf, pat, pids, pos);
	}

	return TSS_SUCCESS;
}

/**
 * PAT 再構築処理
 *
 * PMT から出力対象チャンネル以外のチャンネル情報を削除し、PAT を再構築する
 */
int RecreatePat(
	unsigned char* buf,					// [in]		読み込んだバッファ
	unsigned char** pat,				// [out]	PAT 情報（再構築後）
	unsigned char* pids,				// [out]	出力対象 PID 情報
	int pos)							// [in]		取得対象 PMT のバッファ中の位置
{
	unsigned char y[LENGTH_CRC_DATA];
	int crc;

	// CRC 計算のためのデータ
	{
		int i;

		// チャンネルによって変わらない部分
		for (i = 0; i < LENGTH_CRC_DATA - 4; i++)
		{
			y[i] = buf[i + 5];
		}
		y[2] = 0x11;

		// チャンネルによって変わる部分
		for (i = 0; i < 4; i++)
		{
			y[LENGTH_CRC_DATA - 4 + i] = buf[pos + i];
		}
	}
	// CRC 計算
	crc = GetCrc32(y, 16);


	// PAT 再構成
	*pat = (unsigned char*)malloc(LENGTH_PACKET);
	memset(*pat, 0xFF, LENGTH_PACKET);

	{
		int i;

		for (i = 0; i < 5; i++)
		{
			(*pat)[i] = buf[i];
		}

		for (i = 0; i < LENGTH_CRC_DATA; i++)
		{
			(*pat)[i + 5] = y[i];
		}
		(*pat)[21] = (crc >> 24) & 0xFF;
		(*pat)[22] = (crc >> 16) & 0xFF;
		(*pat)[23] = (crc >>  8) & 0xFF;
		(*pat)[24] = (crc      ) & 0xFF;
	}

	return TSS_SUCCESS;
}

/**
 * PMT 解析処理
 *
 * PMT を解析し、出力対象の PID を特定する
 */
int AnalyzePmt(
	unsigned char* buf,					// [in]		読み込んだバッファ
	unsigned char* pids)				// [out]	出力対象 PID 情報
{
	unsigned char Nall;
	unsigned char N;
	int pcr;

	Nall = ((buf[6] & 0x0F) << 4) + buf[7];

	// PCR
	pcr = GetPid(&buf[13]);
	pids[pcr] = 1;

	if(0x9 == buf[17] ) {
			int ca_pid;
		        ca_pid = ((buf[17+4] & 0x1f)<<8)|buf[17+5];
			pids[ca_pid] = 1;
	}

	N = ((buf[15] & 0x0F) << 4) + buf[16] + 16 + 1;

	// ES PID
	while (N < Nall + 8 - 4)
	{
		// ストリーム種別が 0x0D（type D）は出力対象外
		if (0x0D != buf[N])
		{
			int epid;
			epid = GetPid(&buf[N + 1]);

			pids[epid] = 1;
		}
		N += 4 + (((buf[N + 3]) & 0x0F) << 4) + buf[N + 4] + 1;
	}

	return TSS_SUCCESS;
}

/**
 * 小文字変換処理
 */
char* ToLower(
	char* s)							// [in]		変換前文字列
{
	char *p;
	for (p = s; *p; p++)
	{
		*p = tolower(*p);
	}
	return (s);
}

/**
 * CRC 計算
 */
int GetCrc32(
	unsigned char* data,				// [in]		CRC 計算対象データ
	int len)							// [in]		CRC 計算対象データ長
{
	int crc;
	int i, j;

	crc = 0xFFFFFFFF;
	for (i = 0; i < len; i++)
	{
		char x;
		x = data[i];

		for (j = 0; j < 8; j++)
		{
			int c;
			int bit;

			bit = (x >> (7 - j)) & 0x1;

			c = 0;
			if (crc & 0x80000000)
			{
				c = 1;
			}

			crc = crc << 1;

			if (c ^ bit)
			{
				crc ^= 0x04C11DB7;
			}

			crc &= 0xFFFFFFFF;
		}
	}

	return crc;
}

/**
 * PID 取得
 */
int GetPid(
	unsigned char* data)				// [in]		取得対象データのポインタ
{
	return ((data[0] & 0x1F) << 8) + data[1];
}


