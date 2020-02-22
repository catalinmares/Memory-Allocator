/*Mares Catalin-Constantin
		Grupa 312CD		  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define MAX 1000

unsigned char *arena;
uint32_t start;
uint32_t arena_size;
const uint32_t gestiune = 3 * sizeof(uint32_t);
uint32_t first_allocation;

void initialize(uint32_t size)
{
	arena = (unsigned char*) calloc (size, sizeof (unsigned char));	// alocam dinamic memorie pentru arena
    start = 0;	// setam indicele de start pe 0
    first_allocation = 1;	// setam indicele pentru prima alocare pe 1
}

void finalize()
{
	free(arena);	// eliberam spatiul alocat la initializare
}

void dump()
{
	uint32_t i, j;
	uint32_t indice = 0, exit = 0;
	for (i = 0; i < (arena_size / 16 + arena_size % 16); i++) 
	{
		printf("%08X\t", indice);	// afisam indicele primului octet de pe rand
		for (j = 0; j < 16; j++) 
		{
			if(arena_size == j + indice) 
			{
				exit = 1;	// daca am afisat deja toti octetii iesim din cele 2 for-uri
				break;
			}
			printf("%02X ", *(arena + indice + j));
			if (j == 7) 
			{
				printf(" ");	// afisam un spatiu suplimentar intre octetii 8 si 9
			}
		}
		if (exit) 
		{
			printf("\n");
			break;
		}
		indice += 16;	// incrementam indicele primului octet cu 16
		printf("\n");
	}
}


void alloc(uint32_t size)
{
    unsigned char* charp; // pointer pentru parcurgere
    uint32_t* intp; // pointer pentru intregii din gestiune
    uint32_t index_date; // indexul de inceput al datelor alocate
    uint32_t found = 0;
    
    charp = arena + start; // ne pozitionam pe primul bloc sau daca nu avem niciun bloc, ne pozitionam pe inceputul arenei

    if(arena_size < gestiune + size) // verificam daca am initializat suficient de multi octeti pentru cel putin o alocare
    {
        printf("0\n");	// afisam 0 pentru ca nu se poate efectua alocarea

        return;
    }

    if(first_allocation) // verificam daca suntem la prima alocare
    {
        uint32_t* very_first_block = (uint32_t*) charp; // pointer catre noul si primul bloc din arena
        
        *very_first_block = 0;	// setam indicele blocului urmator pe 0
        *(very_first_block + 1) = 0;	// setam indicele blocului anterior pe 0
        *(very_first_block + 2) = size; // setam indicele dimensiunii sectiunii de date a noului bloc
        first_allocation = 0; // devine 0 pentru ca la urmatoarea alocare sa nu mai intre pe acest caz
        
        index_date = (unsigned char*) very_first_block + gestiune - arena; // diferenta de adrese dintre inceputul blocului de date si inceputul arenei
        printf("%d\n", index_date);

        return;
    }

    if (start >= gestiune + size) // verificam daca avem loc sa alocam inaintea primului bloc
    {
        uint32_t* first_block = (uint32_t*) charp; // adresa primului bloc

        *(first_block + 1) = 0; // setam indecele blocului anterior pe 0

        uint32_t* new_first_block = (uint32_t*) arena; // adresa noului bloc
        
        *(new_first_block + 2) = size; // adaugam in gestiunea noului bloc dimensiunea blocului de date
        *new_first_block = start; // indicele blocului urmator devine indicele de start dinainte adaugaurii noului bloc

        start = 0; // aducem startul la inceputul arenei
        
        index_date = gestiune; // indicele de inceput al noului prim bloc din arena 
        printf("%d\n", index_date);
        
        return;
    }

    intp = (uint32_t*) charp; // pointer catre intreg pentru valorile stocate in gestiune
    
    uint32_t* block_dreapta;	// pointer catre gestiunea blocului din dreapta (folosit in parcurgere)
    uint32_t* block_stanga;		// pointer catre gestiunea blocului din stanga (folosit in parcurgere)
    unsigned char* first_free_byte; 	// pointer catre primul octet liber dupa blocul din stanga

    while (*intp != 0) // cat timp valoarea de la intregul care contine indicele catre urmatorul bloc e nenula parcurgem arena
    {
        charp = arena + *intp; // ne pozitionam pe primul octet din gestiunea urmatorului bloc
        
        block_dreapta = (uint32_t*) charp;	// initializam pointerul catre blocul din dreapta
        block_stanga = intp;	// initializam pointerul catre blocul din stanga
        first_free_byte = (unsigned char*) block_stanga + gestiune 
        + *(block_stanga + 2);	// initializam pointerul catre primul octet liber dupa blocul din stanga
        
        uint32_t spatiu_liber = (unsigned char*) block_dreapta 
        - first_free_byte;	// intreg care ne arata cat spatiu liber se afla intre blocuri
        
        uint32_t spatiu_de_alocat = gestiune + size;	// intreg care ne arata cat spatiu trebuie stocat

        if (spatiu_liber >= spatiu_de_alocat)
        {
            found = 1;	// daca gasim spatiu intre blocuri iesim din parcurgere
            break;
        }
        
        intp = (uint32_t*) charp;	// pointeaza catre adresa urmatorului bloc
    }

    if(found)	// alocarea intre blocuri
    {
        uint32_t new_block_index = first_free_byte - arena; // stocam indicele noului bloc pe care il introducem

        unsigned char* charpointer = arena + new_block_index;	// pointer catre noul bloc

	    uint32_t* new_block = (uint32_t*) charpointer;	// pointer catre primul intreg din gestiunea noului bloc

        *new_block = (unsigned char*) block_dreapta - arena; // setam indicele blocului urmator pe blocul din dreapta
        *(new_block + 1) = (unsigned char*) block_stanga - arena;	// setam indicele blocului anterior pe blocul din stanga
        *(new_block + 2) = size;	// setam dimensiunea blocului de date

        *block_stanga = new_block_index;	// setam indicele blocului urmator in gestiunea blocului din stanga catre noul bloc
        *(block_dreapta + 1) = new_block_index;	// setam indicele blocului anterior in gestiunea blocului din dreapta catre noul bloc

        index_date = first_free_byte + gestiune - arena; // setam indexul returnat de functie pe primul octet de date
        printf("%d\n", index_date);

        return;
    }
    
    uint32_t* last_block = (uint32_t*) charp; // pointer catre inceputul ultimului bloc alocat anterior
    
    if (charp + gestiune + *(last_block + 2) + gestiune + size 
    									<= arena + arena_size) // verificam daca mai incape un bloc de dimensiunea data
    {
        charp += *(last_block + 2) + gestiune; // mutam pointerul la inceputul noului bloc
        
        uint32_t* new_last_block = (uint32_t*) charp; // pointer catre inceputului noului bloc
        
        *(new_last_block + 1) = (unsigned char*) last_block - arena; // indicele anterior al noului bloc devine indicele vechiului bloc
        *(new_last_block + 2) = size; // indicele dimensiunii noului bloc devine dimensiunea alocata
        *last_block = (unsigned char*) new_last_block - arena; // indicele urmator al blocului anterior devine indicele noului bloc
        
        index_date = (unsigned char*) new_last_block + gestiune - arena;	// setam indexul returnat de functie pe primul octet de date
        printf("%d\n", index_date);

        return;
    }
    
    printf("0\n");	// afisam 0 daca nu putem aloca pe niciun caz

    return;
}

void FREE(uint32_t index)
{
	unsigned char* charp; // pointer pentru parcurgere
	uint32_t i;

    charp = arena + index - gestiune; // ne pozitionam pe primul octet din gestiunea blocului de sters;
    
    uint32_t* block_to_free = (uint32_t*) charp; // pointer catre primul intreg din gestiunea blocului de sters
    uint32_t to_free = *(block_to_free + 2); // retinem dimensiunea datelor din blocul de eliberat

    charp = arena + index; // ne pozitionam pe primul octet de date pentru a incepe stergerea datelor
        
    for (i = 0; i < to_free; i++)
    {
        *(charp + i) = 0; // setam pe 0 fiecare octet de date
    }

    *(block_to_free + 2) = 0; // setam pe 0 si dimensiunea datelor a blocului pe care il stergem

    if (*block_to_free == 0 && *(block_to_free + 1) == 0 && 
    									*(arena + start) != 0) // daca sunt 2 blocuri cel de-al doilea are indicii 0, se impune conditie suplimentara
    {
        charp = arena + start; // ne pozitionam pe primul bloc din arena
        
        uint32_t* first_block = (uint32_t*) charp;	// pointer catre primul intreg din gestiunea primului bloc din 
        
        *first_block = 0; // setam indicele blocului urmator pe 0

        return;
    }


    if (*block_to_free == 0 && *(block_to_free + 1) == 0) // daca e singurul bloc din arena are indicii pentru anteriorul si urmatorul 0
    {
        first_allocation = 1; // resetam pentru o arena fara niciun bloc de memorie alocat
        start = 0;	// setam indicele de start pe 0 pentru ca am eliberat singurul bloc din arena

        return;
    }

    if (*block_to_free == 0 && *(block_to_free + 1) != 0) // verificam daca e ultimul bloc din arena
    {   
        charp = arena + *(block_to_free + 1); // ne pozitionam pe penultimul bloc din arena
        
        uint32_t* block_before_last = (uint32_t*) charp;	// pointer catre primul intreg din gestiunea penultimului bloc
        
        *block_before_last = 0; // indicele catre urmatorul bloc devine 0
        *(block_to_free + 1) = 0; // setam pe 0 indicele blocului anterior din gestiunea blocului de sters

        return;
    }

    uint32_t block_index = (unsigned char*) block_to_free - arena;

    if (*block_to_free != 0 && *(block_to_free + 1) == 0 && 
    									block_index != start) // verificam daca e al doilea bloc din arena
    {
        charp = arena + *block_to_free;	// ne pozitionam pe urmatorul bloc

        uint32_t* next_block = (uint32_t*) charp;

        charp = arena + start + *(block_to_free + 1);	// ne pozitionam pe blocul anterior

        uint32_t* previous_block = (uint32_t*) charp;

        *(next_block + 1) = (unsigned char*) previous_block - arena;	// setam indicele blocului anterior din gestiunea blocului urmator catre blocul anterior
        *previous_block = (unsigned char*) next_block - arena;	// setam indicele blocului urmator din gestiunea blocului anterior catre blocul urmator

        *block_to_free = 0;	// setam indicele blocului urmator din gestiunea blocului de sters pe 0
        *(block_to_free + 1) = 0;	// setam indicele blocului anterior din gestiunea blocului de sters pe 0

        return;
    }

    if (index - gestiune == start) // verificam daca e primul bloc din arena (mai sunt si alte blocuri dupa)
    {
        charp = arena + *block_to_free; // ne pozitionam pe al doilea bloc din arena

        uint32_t* block_after_first = (uint32_t*) charp;

        *(block_after_first + 1) = 0; // indicele catre blocul anterior devine 0
        
        start = *block_to_free; // setam startul pe primul octet de gestiune al celui de-al doilea bloc
        
        *block_to_free = 0; // setam pe 0 indicele blocului urmator din gestiunea blocului de sters

        return;
    }

    if (*block_to_free != 0 && *(block_to_free + 1) != 0) // verificam daca blocul se afla intre alte doua blocuri
    {
        uint32_t index_block_before = *(block_to_free + 1); // index de inceput al blocului anterior
        
        uint32_t index_block_after = *block_to_free; // index de inceput al blocului anterior
        
        charp = arena + index_block_before; // ne pozitionam pe primul octet de gestiune al blocului anterior

        uint32_t* block_before = (uint32_t*) charp;

        *block_before = index_block_after; // setam indexul blocului urmator din gestiunea blocului dinainte pe blocul urmator celui de eliberat

        charp = arena + index_block_after; // ne pozitionam pe primul octet de gestiune al blocului succesiv

        uint32_t* block_after = (uint32_t*) charp;

        *(block_after + 1) = index_block_before; // setam indexul blocului anterior din gestiunea blocului succesiv pe blocul anterior celui de eliberat

        *block_to_free = 0; // setam pe 0 indicele pentru blocul urmator din gestiunea blocului de eliberat
        *(block_to_free + 1) = 0; // setam pe 0 indicele pentru blocul anterior din gestiunea blocului de eliberat
    }


}

void fill(uint32_t index, uint32_t size, uint32_t value)
{
	unsigned char* charp;
	uint32_t i;

    charp = arena + index - gestiune; // ne pozitionam pe blocul de date de la care incepem sa umplem

    uint32_t* block_to_fill = (uint32_t*) charp;

    charp = arena + index;

    uint32_t data_size = *(block_to_fill + 2);

    while(size)
    {
        if(data_size >= size)
        {
            for (i = 0; i < size; i++)
            {
                *(charp + i) = value; // umplem octetii de date cu valoarea data
            }

            return;
        }

        else
        {
            for (i = 0; i < data_size; i++)
            {
                *(charp + i) = value; // umplem cati octeti de date avem
            }
            
            size -= data_size; // scadem size pentru a sti cat mai avem de umplut
            
            uint32_t next_block_index = *block_to_fill; // scoate indexul urmatorului bloc pentru a umple in continuare
            
            if (next_block_index == 0)
            {
                return;
            }

            charp = arena + next_block_index; // ne pozitionam pe urmatorul bloc
            block_to_fill = (uint32_t*) charp; 
            data_size = *(block_to_fill + 2); // salvam noua dimensiune de date a noului bloc
            charp = arena + next_block_index + gestiune; // ne pozitionam pe primul octet de date al noului bloc
        }
    }


}
void parse_command(char* cmd)
{
    const char* delims = " \n";

    char* cmd_name = strtok(cmd, delims);
    if (!cmd_name) {
        goto invalid_command;
    }

    if (strcmp(cmd_name, "INITIALIZE") == 0) {
        char* size_str = strtok(NULL, delims);
        if (!size_str) {
            goto invalid_command;
        }
        uint32_t size = atoi(size_str);
        arena_size = size;
        initialize(size);

    } else if (strcmp(cmd_name, "FINALIZE") == 0) {
        finalize();

    } else if (strcmp(cmd_name, "DUMP") == 0) {
        dump();

    } else if (strcmp(cmd_name, "ALLOC") == 0) {
        char* size_str = strtok(NULL, delims);
        if (!size_str) {
            goto invalid_command;
        }
        uint32_t size = atoi(size_str);
        alloc(size);

    } else if (strcmp(cmd_name, "FREE") == 0) {
        char* index_str = strtok(NULL, delims);
        if (!index_str) {
            goto invalid_command;
        }
        uint32_t index = atoi(index_str);
        FREE(index);

    } else if (strcmp(cmd_name, "FILL") == 0) {
        char* index_str = strtok(NULL, delims);
        if (!index_str) {
            goto invalid_command;
        }
        uint32_t index = atoi(index_str);
        char* size_str = strtok(NULL, delims);
        if (!size_str) {
            goto invalid_command;
        }
        uint32_t size = atoi(size_str);
        char* value_str = strtok(NULL, delims);
        if (!value_str) {
            goto invalid_command;
        }
        uint32_t value = atoi(value_str);
        fill(index, size, value);

    } else {
        goto invalid_command;
    }

    return;

invalid_command:
    printf("Invalid command: %s\n", cmd);
    exit(1);
}

int main(void)
{
    ssize_t read;
    char* line = NULL;
    size_t len;

    /* parse input line by line */
    while ((read = getline(&line, &len, stdin)) != -1) {
        /* print every command to stdout */
        printf("%s", line);

        parse_command(line);
    }

    free(line);

    return 0;
}