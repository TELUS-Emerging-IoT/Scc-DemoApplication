# Scc-DemoApplication
This is a guide on how to setup and run the demo3 application utilizing the GD library.

The scc toolkit provides various security key features abstracted for easy implementation. To compile and run the application do the following.

1. On the raspberry pi, cd to the following directory:
```
/home/pi/Downloads/demo/scc-lib/demo-src
```
2. Compile the demo3.cpp file:

In the .../scc-lib/demo-src folder, issue the following command:

```
g++ demo3.cpp -lscc-toolkit -lssl -lcrypto -o demo3 -std=c++17

```
3. run the demo3 executable via the command: 

```
./demo3
```
4. The output should look like the following:

![alt text](images/4exampleout.png)

If the program throws a CME error, then the BG96 may require a firmware upgrade, please see the following tutorial:

https://github.com/TELUS-Emerging-IoT/TELUS-IoT-BG96-Firmware-Update

## demo3 output
For reference, the output of the code is included on watchdox alongside some additional comments on what each section does. Overall demo3 showcases the various keys availible to the user. More information can be found within the demo3 source file and the scc-toolkit headers.

## Optional
If you require a clean version of the demo application it can be downloaded from workspaces (watchdocs). The scc-lib.zip contains the demo files.
![alt text](images/1Downloadzip.png)

Unzip and move the folder to the Raspberry pi
![alt text](images/2movefilesover.png)
