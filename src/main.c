#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "libsecr-common.h"

static void DisplayUsageHelp(const char* ARGV0){
	printf("Syntax:\n\t'%s <Signed KELF> <KELF to be signed>': clone KELF encryption from first to second file\n"
			"\n\t'%s --manual <KELF to be signed>': manually change the Kbit and Kc fields\n\n"
			"Note: Both KELFs must have the same Kbit and Kc fields, and must be used on the same memory card.\n",ARGV0, ARGV0);
}

static int GetKbitAndKc(const char *path, unsigned char *Kbit, unsigned char *Kc){
	int result, offset;
	FILE *file;
	unsigned char OffsetByte;
	SecrKELFHeader_t header;

	result=0;
	if((file=fopen(path, "rb"))!=NULL){
		if(fread(&header, sizeof(SecrKELFHeader_t), 1, file)==1){
			offset=0x20;
			if(header.BIT_count > 0) offset+=header.BIT_count*0x10;
			if((*(unsigned int*)&header.flags)&1){
				fseek(file, offset, SEEK_SET);
				result=fread(&OffsetByte, sizeof(OffsetByte), 1, file)==1?0:EIO;
				offset+=OffsetByte+1;
			}
			if(((*(unsigned int*)&header.flags)&0xF000)==0) offset+=8;

			if(result==0){
				fseek(file, offset, SEEK_SET);
				if((result=fread(Kbit, 1, 16, file)==16?0:EIO)==0){
					result=fread(Kc, 1, 16, file)==16?0:EIO;
				}
			}
		}
		else result=EIO;

		fclose(file);
	}
	else result=ENOENT;

	return result;
}

static int SetKbitAndKc(const char *path, unsigned char *Kbit, unsigned char *Kc){
	int result, offset;
	FILE *file;
	unsigned char OffsetByte;
	SecrKELFHeader_t header;

	result=0;
	if((file=fopen(path, "rb+"))!=NULL){
		if(fread(&header, sizeof(SecrKELFHeader_t), 1, file)==1){
			offset=0x20;
			if(header.BIT_count > 0) offset+=header.BIT_count*0x10;
			if((*(unsigned int*)&header.flags)&1){
				fseek(file, offset, SEEK_SET);
				result=fread(&OffsetByte, sizeof(OffsetByte), 1, file)==1?0:EIO;
				offset+=OffsetByte+1;
			}
			if(((*(unsigned int*)&header.flags)&0xF000)==0) offset+=8;

			if(result==0){
				fseek(file, offset, SEEK_SET);
				if((result=fwrite(Kbit, 1, 16, file)==16?0:EIO)==0){
					result=fwrite(Kc, 1, 16, file)==16?0:EIO;
				}
			}
		}
		else result=EIO;

		fclose(file);
	}
	else result=ENOENT;

	return result;
}

static void DisplayErrorMessage(const char *file, int code){
	switch(code){
		case ENOENT:
			printf("Can't open input file %s\n", file);
			break;
		case EIO:
			printf("An I/O error occurred when accessing file: %s\n", file);
			break;
		default:
			printf("An internal error occurred. Please report!\nCode: %d\n", code);
	}
}

static int ManualKbit_and_KcPrompt(unsigned char *Kbit, unsigned char *Kc){
#define A Kbit
#define B Kc
    fflush(stdin);
    int x=0, kbitcnt, kcontentcnt;
    char T;
	puts("Manual KELF Encryption selected\n"
		 "-------------------------------\n");
    puts("Input Kbit now (example: '0b 0c fa d4 5c ff 33 e1 56 66 7a 8b 1c 0d 4e 0f')\n");
    kbitcnt = scanf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
            &A[0], &A[1], &A[2], &A[3], &A[4], &A[5], &A[6], &A[7], &A[8],
            &A[9], &A[10], &A[11], &A[12], &A[13], &A[14], &A[15]
          );
    puts("Input Kc now (example: '0f 4e 1c 0c fa d4 8b 7a 66 0d 0b 5c ff 33 e1 56')\n");
    kcontentcnt = scanf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
            &B[0], &B[1], &B[2], &B[3], &B[4], &B[5], &B[6], &B[7], &B[8],
            &B[9], &B[10], &B[11], &B[12], &B[13], &B[14], &B[15]
          );
    if (kbitcnt != 16 || kcontentcnt != 16)
        fprintf(stderr, "WARNING (%d|%d): Seems like you didn't input a full value, please check before proceeding\n", kbitcnt, kcontentcnt);

    printf("\nThese are the introduced values. CHECK CAREFULLY BEFORE APPLYING"
           "\n-------------------------------\nKbit: ");
    for (x=0; x<16; x++)
        printf("%02X ", Kbit[x]);

    printf("\nKc  : ");
    for (x=0; x<16; x++)
        printf("%02X ", Kc[x]);
    fflush(stdin);
    sleep(1);
    puts("\nPress enter to apply or any other key to abort\n");
    scanf("%c", &T);
    return (T == '\n');
#undef A
#undef B
}

int main(int argc, char *argv[]){
	unsigned char Kbit[16], Kc[16];
	memset(Kbit, 0, 16);
	memset(Kc, 0, 16);
	int result;

	printf(	"KELF twin signer v1.01\n"
			"----------------------\n\n");

	if(argc!=3){
		DisplayUsageHelp(argv[0]);
		return EINVAL;
	}

	if (!strcmp(argv[1], "--manual")){
		if(ManualKbit_and_KcPrompt(Kbit, Kc))
		{
			if((result=SetKbitAndKc(argv[2], Kbit, Kc))==0){
				printf("Kbit and Kc transferred successfully!\n");
			}
			else{
				DisplayErrorMessage(argv[2], result);
			}
		} else {
			puts("Manual process aborted!\n");
			return 1;
		}
	}
	else if((result=GetKbitAndKc(argv[1], Kbit, Kc))==0){
		printf(	"KELF %s opened.\n"
				"Kbit:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n"
				"Kc  :\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n\n"
				, argv[1]
				, Kbit[0], Kbit[1], Kbit[2], Kbit[3], Kbit[4], Kbit[5], Kbit[6], Kbit[7], Kbit[8], Kbit[9], Kbit[10], Kbit[11], Kbit[12], Kbit[13], Kbit[14], Kbit[15]
				, Kc[0], Kc[1], Kc[2], Kc[3], Kc[4], Kc[5], Kc[6], Kc[7], Kc[8], Kc[9], Kc[10], Kc[11], Kc[12], Kc[13], Kc[14], Kc[15]);

		if((result=SetKbitAndKc(argv[2], Kbit, Kc))==0){
			printf("Kbit and Kc transferred successfully!\n");
		}
		else{
			DisplayErrorMessage(argv[2], result);
		}
	}
	else{
		DisplayErrorMessage(argv[1], result);
	}

	return result;
}
