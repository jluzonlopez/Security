#include <openssl/bio.h> // para hacer bio64
#include <openssl/evp.h>
#include <openssl/sha.h> // para hacer sha512
#include <openssl/rsa.h> // para RSA
#include <openssl/pem.h> // para formato PEM
#include <openssl/err.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


//T = (ID||hash)
#define T_LONG 83
//(4096/8)-(19+64)-3
//len(T) = (19+64)
#define PS_LONG 426


unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
																0x06, 0x09, 0x60, 0x86,
																0x48, 0x01, 0x65, 0x03,
																0x04, 0x02, 0x03, 0x05,
																0x00, 0x04, 0x40};

// Funciones
//leer en base64
int read64(char *rf, unsigned char *buffer, long int buffer_size){
	FILE *f;
	int readed;
	BIO *bio64, *bio_out;

	f = fopen(rf,"r");
	if(f){
  	bio64 = BIO_new(BIO_f_base64());
		bio_out = BIO_new_fp(f,BIO_NOCLOSE);
		BIO_push(bio64,bio_out);
	}else{
		fprintf(stderr,"Error openining BIO file\n");
		return -1;
	}

	//empiezo a leer
	readed = BIO_read(bio64,buffer,buffer_size);
	if(readed < 0 && !BIO_should_retry(bio64)){
		return -1;
	}

	fclose(f);
	BIO_free_all(bio64);
	return readed;
}


//escribir en base64
void write64(char *message,long int mess_size){
	BIO *bio64;
	BIO *bio_out;

	bio64 = BIO_new(BIO_f_base64());
	bio_out = BIO_new_fp(stdout,BIO_NOCLOSE);
	BIO_push(bio64,bio_out);
	write(1,"---BEGIN SRO SIGNATURE---\n",strlen("---BEGIN SRO SIGNATURE---\n"));
	BIO_write(bio64,message,mess_size);

	BIO_flush(bio64);
	BIO_free_all(bio64);

	write(1,"---END SRO SIGNATURE---\n",strlen("---END SRO SIGNATURE---\n"));
}

//hash sha512
unsigned char* hash(char *fichdat, long int nom_fich_long, unsigned char *buff){
	int fich_dat;
	int readed;
	char text[64];
	unsigned char digest[SHA512_DIGEST_LENGTH];
	unsigned char T[T_LONG];
	memset(digest, 0, sizeof(digest));


	SHA512_CTX	context;
	SHA512_Init(&context);

	fich_dat = open(fichdat,O_RDONLY);
	if(fich_dat > 0){
			while ((readed = read(fich_dat,text,sizeof(text))) > 0){
				SHA512_Update(&context,text,readed);
			}
			close(fich_dat);
	}else{
		fprintf(stderr,"Error openining file\n");
		printf("\n");
	}

	SHA512_Update(&context,fichdat,nom_fich_long);
	SHA512_Final(digest,&context);

	//Padding
	memcpy(T,EMSASHA512ID,sizeof(EMSASHA512ID));
	memcpy(T+sizeof(EMSASHA512ID),digest,SHA512_DIGEST_LENGTH);

	buff[0]=0x00;
	buff[1]=0x01;

	memset(buff+2,0xFF,PS_LONG);
	buff[PS_LONG+2]=0x00;
	memcpy(buff+PS_LONG+3,T,sizeof(T));

	return buff;
}

//firmar las hash con RSA
int signRSA(long int hash_size, unsigned char *hash, unsigned char *encrypted, char *privkey){
	FILE *k;
	RSA *rsa = NULL;
	unsigned char cipher[128];

	k = fopen(privkey,"r");
	if(!k){
		fprintf(stderr,"Error openining key file\n");
		return -1;
	}

	rsa = PEM_read_RSAPrivateKey(k,&rsa,NULL,NULL);

	if(RSA_private_encrypt(hash_size,hash,encrypted,rsa,RSA_NO_PADDING)<0){
		printf ("%s\n", ERR_error_string (ERR_get_error (), (char *) cipher)); //openssl errstr 0x0406B07A para ver el error
		fprintf(stderr,"Error encrypting\n");
		return -1;
	}

	write64((char *)encrypted,hash_size);
	return 0;

}

int decRSA(long int dec_size, unsigned char *hash, unsigned char *decrypted, char *pubkey){
	FILE *k;
	RSA *rsa = NULL;
	unsigned char cipher[128];

	k = fopen(pubkey,"r");
	if(!k){
		fprintf(stderr,"Error openining key file\n");
		return -1;
	}

	rsa = PEM_read_RSA_PUBKEY(k,&rsa,NULL,NULL);

	if(RSA_public_decrypt(dec_size,hash,decrypted,rsa,RSA_NO_PADDING)<0){
		printf ("%s\n", ERR_error_string (ERR_get_error (), (char *) cipher)); //openssl errstr 0x0406B07A para ver el error
		fprintf(stderr,"Error encrypting\n");
		return -1;
	}
	return 0;
}

int verify(unsigned char *h1, unsigned char *h2, long int h_size){
	for(int i = 0; i < h_size; i++){
		if(h1[i] != h2[i]){
			return -1;
		}
	}
	return 1;
}

// Programa principal
int main (int argc,char **argv){
	unsigned char hash_t[512];
	unsigned char d_hash_t[512];
	unsigned char encrypted[1024*5];
	unsigned char decrypted[1024*5];
	char *file_signed;
	char *key;
	char *file;
	int readed;

	if (argc < 3){
    	printf("Usage: ./sign [-v signature] datafile keyfile \n");
  }else{
			if(argc == 3){
				file = argv[1];
				key = argv[2];


				hash(file,strlen(file),hash_t);

				if(signRSA(sizeof(hash_t),hash_t,encrypted,key) < 0){
					fprintf(stderr,"Sign Failed\n");
				}
			}else if(argc == 5){
				file_signed = argv[2];
				file = argv[3];
				key = argv[4];
				
				readed = read64(file_signed,decrypted,sizeof(decrypted));
				if(decRSA(readed,decrypted,d_hash_t,key) < 0 ){
					fprintf(stderr,"Decrypting error\n");
				}

				//Verify
				hash(file,strlen(file),hash_t);
				if(verify(hash_t,d_hash_t,sizeof(hash_t)) < 0){
					fprintf(stderr,"Verify error¡\n");
				}

			}else{
				printf("Usage: ./sign [-v signature] datafile keyfile \n");
			}
	}
}
