In order to update the libradamsa shared object, clone the radamsa repo

`git clone https://gitlab.com/akihe/radamsa.git`

Patch the changes into the directory using the mutator.patch file in this 
directory

`git apply mutator.patch`

Make any changes to the code that you need to and then compile using
`make libradamsa-test`. The shared object will be created in the 'lib' 
directory. 

If you make any changes be sure to create a new patch and replace it with the
current one. 