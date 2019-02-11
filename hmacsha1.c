#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/*definir constantes*/
#define IPAD 0x36
#define OPAD 0x5C

#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCK_LENGTH 64

void hmacsha1(char *fichtxt, char *fichkey){


	FILE *fich_key;
	FILE *fich_txt;
	unsigned char key[64];
	int key_len;
	char text[64];
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
	int i;
	int readed;
	unsigned char digest[20];
	memset(key, 0, 64);
	memset(digest, 0, sizeof(digest));


	//Leemos la key del fichero (maximo 64 caracteres)
	fich_key = fopen(fichkey,"r");
	if (fich_key){
		fread(key,SHA1_BLOCK_LENGTH,1,fich_key);
	}else{
		printf("%s","Error openining file");
	}
 	key_len = SHA1_BLOCK_LENGTH;
  fclose(fich_key);


    //Montamos la XOR de la funcion con la key y las constantes
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
  bcopy( key, k_opad, key_len);

    for (i=0; i<64; i++) {
     	k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

	//ipad_hash
	SHA_CTX	context;
	SHA1_Init(&context);
	SHA1_Update(&context,k_ipad,SHA1_BLOCK_LENGTH);

	//Alimentamos la hash con el fichero de texto
	fich_txt = fopen(fichtxt,"r");
	if(fich_txt){
			readed = fread(text,sizeof(text),1,fich_txt);
			while (readed != 0){
				SHA1_Update(&context,text,readed);
				readed = fread(text,sizeof(text),1,fich_txt);
			}
			fclose(fich_txt);
	}else{
		printf("%s","Error openining file txt");
		printf("\n");
	}
	SHA1_Final(digest,&context);

	//opad_hash
	SHA1_Init(&context);
	SHA1_Update(&context,k_opad,SHA1_BLOCK_LENGTH);
	SHA1_Update(&context,digest,sizeof(digest));
	SHA1_Final(digest,&context);

	//Mostramos el resultado final en hexa
	printf("%s","Digest is: ");
	for(i=0; i < sizeof(digest) ;i++){
		printf("%02x",digest[i]);
	}
	printf("\n");
}

/*programa principal*/
int main (int argc,char **argv)
{
	/*variables: tipo *nombre */
	if (argc != 3){
    	printf("Metodo de uso: ./hmacsha1 fichtxt key \n");
  	}else{
  		hmacsha1(argv[1],argv[2]);
	}
}
