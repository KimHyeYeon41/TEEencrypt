/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEEncrypt.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEEncrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	char root_path[100] = "/root/";
	int cipher_key;

	
	if(strcmp(argv[1],"-e") == 0){
		res = TEEC_InitializeContext(NULL, &ctx);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	
		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, err_origin);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;

		strcat(root_path, argv[2]);
		FILE *fp = fopen(root_path, "r");
		fgets(plaintext, len, fp);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		fclose(fp);

		res = TEEC_InvokeCommand(&sess, TA_TEEEncrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		

		FILE *fp_encrypt = fopen("/root/ciphertext.txt", "w"); 
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		fputs(ciphertext, fp_encrypt);
		fclose(fp_encrypt);	

		FILE *fp_key = fopen("/root/key.txt", "w");
		cipher_key = op.params[1].value.a;
		fprintf(fp_key, "%d", cipher_key);
		fclose(fp_key);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	}

	else if(strcmp(argv[1], "-d") == 0){
		res = TEEC_InitializeContext(NULL, &ctx);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	
		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, err_origin);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;

		
		strcat(root_path, argv[3]);
		FILE *fp_key = fopen(root_path, "r");
		fscanf(fp_key, "%d", &cipher_key);
		op.params[1].value.a = cipher_key;
		fclose(fp_key);

		char root_path2[100] = "/root/";
		strcat(root_path2, argv[2]);
		FILE *fd = fopen(root_path2, "r");
		fgets(ciphertext, len, fd);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		fclose(fd);

		res = TEEC_InvokeCommand(&sess, TA_TEEEncrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		
		FILE *fp_decrypt = fopen("/root/decrypttext.txt", "w"); 	
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		fputs(plaintext, fp_decrypt); 
		fclose(fp_decrypt); 

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	}
	

	return 0;
}
