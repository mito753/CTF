#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NOTES 14
char * notes[MAX_NOTES];
int tracker = 0;

int init(){
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
        alarm(60*3);
}
int choice(){
        int c;
        printf(">> ");
        scanf("%d",&c);
        return c;
}
int menu(){
        puts("Select an action");
        puts("(1) create a note");
        puts("(2) delete a note");
        puts("(3) edit a note");
        puts("(4) view a note");
        puts("(5) exit");
}
int read_index(){
        int index;
        puts("index : ");
        printf(">> ");
        scanf("%d",&index);
        if((index>=0)&&(index<MAX_NOTES)){
                return index;
        }
        else {
                puts("wrong index");
                return -1;
        }
}
int create(){
        char * name;
        char content[0x80];
        int size;
        int index;
        index = read_index();
        if((index!=-1)&&(!notes[index])){
                puts("size : ");
                printf(">> ");
                scanf("%d",&size);
                if((size>0)&&(size<0x90)){
                        notes[index] = malloc(size);
                        puts("content : ");
                        printf(">> ");
                        read(0,content,size);
                        content[strlen(content)-1] = '\0';
                        strcpy(notes[index],content);
                }
                else {
                        puts("That's too much !");
                }
        }
        else {
                puts("wrong index");
        }
}
int delete(){
        int index;
        index = read_index();
        if(index != -1){
                free(notes[index]);
                puts("note deleted");
        }

}
int edit(){
        int index;
        index = read_index();
        if(index != -1){
                puts("New content : ");
                printf(">> ");
                read(0,notes[index],strlen(notes[index]));
                puts("note updated !");
        }
}
int view(){
        int index = read_index();
        if((notes[index])&&(index!=-1)){
                puts(notes[index]);
        }
}

int main(){
        int c;
        init();
        while(1){
                menu();
                c = choice();
                switch(c) {
                        case 1 :
                                create();
                                break;
                        case 2:
                                delete();
                                break;
                        case 3:
                                edit();
                                break;
                        case 4:
                                view();
                                break;
                        default:
                                exit(1);
                }
        }
}
