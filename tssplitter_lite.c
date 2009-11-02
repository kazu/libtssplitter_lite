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
 * �����p�\����
 */
typedef struct {
	char* src;				// ���̓t�@�C��
	char* dst;				// �o�̓t�@�C��
	char* sid;				// �o�͑Ώۃ`�����l���ԍ�
	int useFifo;			// FIFO �g�p�t���O
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
	int argc,							// [in]		�����̌�
	char** argv)						// [in]		����
{
	PARAM param;

	int result;							// ��������

	// �p�����[�^���
	result = AnalyzeParam(argc, argv, &param);
	if (TSS_SUCCESS != result)
	{
		return result;
	}

	// �������s
	result = execute(&param);

	return result;
}

/**
 * �g�p���@���b�Z�[�W�o��
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
 * �p�����[�^���
 */
int AnalyzeParam(
	int argc,							// [in]		�����̌�
	char** argv,						// [in]		����
	PARAM* param)						// [out]	�������f�[�^
{
	// �����`�F�b�N
	if ((4 != argc) && (5 != argc))
	{
		show_usage();
		return TSS_ERROR;
	}

	param->src		= argv[1];
	param->dst		= argv[2];
	param->sid		= argv[3];

	// FIFO �𗘗p����ꍇ
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
 * ������
 */
int execute(
	PARAM* param)						// [in]		�������f�[�^
{
	int result;

	int sfd					= -1;		// �t�@�C���L�q�q�i�ǂݍ��ݗp�j
	int dfd					= -1;		// �t�@�C���L�q�q�i�������ݗp�j

	unsigned char pids[MAX_PID];
	unsigned char* pat = NULL;

	// ������
	memset(pids, 0, MAX_PID);

	// �ǂݍ��݃t�@�C���I�[�v��
	sfd = _open(param->src, _O_BINARY|_O_RDONLY|_O_SEQUENTIAL);
	if (sfd < 0)
	{
		goto LAST;
	}

	// �������݃t�@�C���I�[�v��
	dfd = _open(param->dst, _O_WRONLY|_O_BINARY|_O_CREAT|_O_TRUNC, _S_IREAD|_S_IWRITE);
	if (dfd < 0)
	{
		goto LAST;
	}

	// �t�@�C������
	result = ReadTs(&sfd, &pat, pids, param->sid);
	if (TSS_SUCCESS != result)
	{
		goto LAST;
	}

	if (false == param->useFifo)
	{
		_lseeki64(sfd, 0, SEEK_SET);
	}

	// �t�@�C���o��
	result = WriteTs(&sfd, &dfd, &pat, pids);
	if (TSS_SUCCESS != result)
	{
		goto LAST;
	}

LAST:
	// �J������
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
 * TS �t�@�C���ǂݍ��ݏ���
 *
 * TS �t�@�C����ǂݍ��݁A�Ώۂ̃`�����l���ԍ��݂̂� PAT �̍č\�z�Əo�͑Ώ� PID �̒��o���s��
 */
int ReadTs(
	int* sfd,							// [in]		�t�@�C���L�q�q�i�ǂݍ��ݗp�j
	unsigned char** pat,				// [out]	PAT ���i�č\�z��j
	unsigned char* pids,				// [out]	�o�͑Ώ� PID ���
	char* sid)							// [in]		�o�͑ΏۃT�[�r�X ID
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
 * TS �t�@�C���������ݏ���
 */
int WriteTs(
	int* sfd,							// [in]		�t�@�C���L�q�q�i�ǂݍ��ݗp�j
	int* dfd,							// [in]		�t�@�C���L�q�q�i�������ݗp�j
	unsigned char** pat,				// [out]	PAT ���i�č\�z��j
	unsigned char* pids)				// [out]	�o�͑Ώ� PID ���
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
			// ����J�E���^�J�E���g�A�b�v
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

		// ���̑� PID
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
 * PAT ��͏���
 *
 * PAT ����͂��A�o�͑Ώۃ`�����l�����܂܂�Ă��邩�`�F�b�N���s���APAT ���č\�z����
 */
int AnalyzePat(
	unsigned char* buf,					// [in]		�ǂݍ��񂾃o�b�t�@
	unsigned char** pat,				// [out]	PAT ���i�č\�z��j
	unsigned char* pids,				// [out]	�o�͑Ώ� PID ���
	char* sid,							// [in]		�o�͑ΏۃT�[�r�X ID
	int* pmt_pid)						// [out]	�T�[�r�X ID �ɑΉ����� PMT �� PID
{
	int pos			= 0;

	// �Ώۃ`�����l������
	{
		int i;
		for (i = 17; i < LENGTH_PACKET - 4; i = i + 4)
		{
			int service_id;

			// �f�[�^�̏I������
			// �Ō�� CRC �̔�������Ȃ��Ƃ����Ȃ��Ȃ�
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

	// PAT �č\�z
	if (NULL == *pat)
	{
		RecreatePat(buf, pat, pids, pos);
	}

	return TSS_SUCCESS;
}

/**
 * PAT �č\�z����
 *
 * PMT ����o�͑Ώۃ`�����l���ȊO�̃`�����l�������폜���APAT ���č\�z����
 */
int RecreatePat(
	unsigned char* buf,					// [in]		�ǂݍ��񂾃o�b�t�@
	unsigned char** pat,				// [out]	PAT ���i�č\�z��j
	unsigned char* pids,				// [out]	�o�͑Ώ� PID ���
	int pos)							// [in]		�擾�Ώ� PMT �̃o�b�t�@���̈ʒu
{
	unsigned char y[LENGTH_CRC_DATA];
	int crc;

	// CRC �v�Z�̂��߂̃f�[�^
	{
		int i;

		// �`�����l���ɂ���ĕς��Ȃ�����
		for (i = 0; i < LENGTH_CRC_DATA - 4; i++)
		{
			y[i] = buf[i + 5];
		}
		y[2] = 0x11;

		// �`�����l���ɂ���ĕς�镔��
		for (i = 0; i < 4; i++)
		{
			y[LENGTH_CRC_DATA - 4 + i] = buf[pos + i];
		}
	}
	// CRC �v�Z
	crc = GetCrc32(y, 16);


	// PAT �č\��
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
 * PMT ��͏���
 *
 * PMT ����͂��A�o�͑Ώۂ� PID ����肷��
 */
int AnalyzePmt(
	unsigned char* buf,					// [in]		�ǂݍ��񂾃o�b�t�@
	unsigned char* pids)				// [out]	�o�͑Ώ� PID ���
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
		// �X�g���[����ʂ� 0x0D�itype D�j�͏o�͑ΏۊO
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
 * �������ϊ�����
 */
char* ToLower(
	char* s)							// [in]		�ϊ��O������
{
	char *p;
	for (p = s; *p; p++)
	{
		*p = tolower(*p);
	}
	return (s);
}

/**
 * CRC �v�Z
 */
int GetCrc32(
	unsigned char* data,				// [in]		CRC �v�Z�Ώۃf�[�^
	int len)							// [in]		CRC �v�Z�Ώۃf�[�^��
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
 * PID �擾
 */
int GetPid(
	unsigned char* data)				// [in]		�擾�Ώۃf�[�^�̃|�C���^
{
	return ((data[0] & 0x1F) << 8) + data[1];
}


