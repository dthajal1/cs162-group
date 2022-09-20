# include <stdio.h>

int main(){
    // int fd = 4;
    // void *ptr = (void *) fd;
    // int *int_ptr = (int *) fd;

    int a = 4;
    int *int_ptr = &a;
    printf("ptr val: %p\n", int_ptr);

    int rv = (int) (long) int_ptr;
    printf("ptr to int: %d\n", rv);


    int *reverse_ptr = (int *) (long) rv;
    printf("int to ptr: %p\n", reverse_ptr);  
    

    // printf("hello world!\n");
    // printf("%d", fd);
    // printf("%d", *int_ptr);
    return 0;
}