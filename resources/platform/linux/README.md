In order to update the libradamsa shared object, clone the radamsa repo
available at: 

https://gitlab.com/akihe/radamsa

Add the following method to the file c/lib.c

```
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                            size_t MaxSize, unsigned int Seed ){
       static bool init = false;
       if(!init){
         radamsa_init();
         init = true;
       }
       return radamsa(Data, Size, Data, MaxSize, Seed);
   }
```

Make any changes to the code that you need to and then compile using
`make libradamsa-test`. The shared object will be created in the 'lib' 
directory. If you make any changes to LLVMFuzzerCustomMutator make sure to
document the changes here as well so future edits contain your changes. 